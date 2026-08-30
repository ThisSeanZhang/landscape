#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "pkg_def.h"
#include "neigh_ip6.h"
#include "neigh_ip6_event.h"
#include "route/route_maps_v6.h"

char LICENSE[] SEC("license") = "GPL";

// ICMPv6 Neighbor Solicitation (RFC 4861)
#define ICMPV6_NEIGHBOR_SOLICIT 135

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

// Solicited-node multicast ff02::1:ff00:0:0:0:0:0/104
// Byte layout: ff 02 00 00 00 00 00 00 00 00 00 01 ff XX XX XX
static __always_inline bool is_solicited_node_multicast(const u8 *addr) {
    return addr[0] == 0xff && addr[1] == 0x02 && addr[2] == 0x00 && addr[3] == 0x00 &&
           addr[4] == 0x00 && addr[5] == 0x00 && addr[6] == 0x00 && addr[7] == 0x00 &&
           addr[8] == 0x00 && addr[9] == 0x00 && addr[10] == 0x00 && addr[11] == 0x01 &&
           addr[12] == 0xff;
}

// RFC 4861: the solicited-node multicast address is derived from the target,
// its last 24 bits must equal the target's last 24 bits.
static __always_inline bool is_target_solicited_node(const u8 *daddr, const u8 *target) {
    return is_solicited_node_multicast(daddr) && daddr[13] == target[13] &&
           daddr[14] == target[14] && daddr[15] == target[15];
}

// Ethernet multicast MAC 33:33:ff:XX:XX:XX for the target's solicited-node
// multicast address.
static __always_inline bool is_target_solicited_node_mac(const u8 *mac, const u8 *target) {
    return mac[0] == 0x33 && mac[1] == 0x33 && mac[2] == 0xff && mac[3] == target[13] &&
           mac[4] == target[14] && mac[5] == target[15];
}

static __always_inline bool is_unspecified_ip6(const u8 *bytes) {
    u8 zero = 0;
    for (int i = 0; i < 16; i++) {
        zero |= bytes[i];
    }
    return zero == 0;
}

static __always_inline bool is_link_local_ip6(const u8 *bytes) {
    return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
}

static __always_inline bool is_multicast_ip6(const u8 *bytes) { return bytes[0] == 0xff; }

static __always_inline bool is_same_mac(const u8 *a, const u8 *b) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] &&
           a[5] == b[5];
}

// Emit one ip6_dao_event for the ringbuf consumer. ip is the DAD NS target,
// mac the Ethernet source of the frame that claimed it.
static __always_inline void emit_ip6_dao_event(u32 ifindex, const u8 *ip, const u8 *mac) {
    struct ip6_dao_event *event = bpf_ringbuf_reserve(&ip6_dao_events, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->ifindex = ifindex;
    __builtin_memcpy(event->ip, ip, sizeof(event->ip));
    __builtin_memcpy(event->mac, mac, sizeof(event->mac));
    __builtin_memset(event->__pad, 0, sizeof(event->__pad));
    bpf_ringbuf_submit(event, 0);
}

SEC("tc/ingress")
int tc_lan_dao(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_lan_dao"
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (current_l3_offset > 0) {
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return TC_ACT_UNSPEC;
        if (eth->h_proto != ETH_IPV6) return TC_ACT_UNSPEC;
    }

    // Snapshot the IPv6 header fields before walking extension headers: the
    // walk below may call bpf_skb_pull_data, which invalidates earlier packet
    // pointers. bpf_skb_load_bytes is used to avoid miscompiled direct reads.
    u8 daddr[16];
    u8 saddr[16];
    if (bpf_skb_load_bytes(skb, current_l3_offset + offsetof(struct ipv6hdr, saddr), saddr,
                           sizeof(saddr))) {
        return TC_ACT_UNSPEC;
    }
    if (bpf_skb_load_bytes(skb, current_l3_offset + offsetof(struct ipv6hdr, daddr), daddr,
                           sizeof(daddr))) {
        return TC_ACT_UNSPEC;
    }

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) {
        return TC_ACT_UNSPEC;
    }

    u8 nexthdr = ip6h->nexthdr;
    u32 l4_offset = current_l3_offset + sizeof(*ip6h);

    // Walk IPv6 extension headers (RFC 8200)
    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM && nexthdr != NEXTHDR_ICMP; i++) {
        if (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING || nexthdr == NEXTHDR_DEST) {
            struct ipv6_opt_hdr *opthdr;
            if (VALIDATE_READ_DATA(skb, &opthdr, l4_offset, sizeof(*opthdr))) {
                return TC_ACT_UNSPEC;
            }
            l4_offset += (opthdr->hdrlen + 1) * 8;
            nexthdr = opthdr->nexthdr;
            continue;
        }
        if (nexthdr == NEXTHDR_FRAGMENT) {
            struct frag_hdr *frag_hdr;
            if (VALIDATE_READ_DATA(skb, &frag_hdr, l4_offset, sizeof(*frag_hdr))) {
                return TC_ACT_UNSPEC;
            }
            u16 raw_off = bpf_ntohs(frag_hdr->frag_off);
            u16 frag_off = raw_off & IPV6_FRAG_OFFSET;
            bool more = raw_off & IPV6_FRAG_MF;
            // Only the first fragment carries the NS header; skip the rest.
            if (frag_off != 0 || !more) return TC_ACT_UNSPEC;
            l4_offset += sizeof(*frag_hdr);
            nexthdr = frag_hdr->nexthdr;
            continue;
        }
        if (nexthdr == NEXTHDR_AUTH) return TC_ACT_UNSPEC;
        break;
    }

    if (nexthdr != NEXTHDR_ICMP) return TC_ACT_UNSPEC;

    // Only handle DAD NS sent to the solicited-node multicast address
    if (!is_solicited_node_multicast(daddr)) return TC_ACT_UNSPEC;

    // DAD NS uses the unspecified source address (RFC 4862)
    if (!is_unspecified_ip6(saddr)) return TC_ACT_UNSPEC;

    struct icmp6hdr *icmp6h;
    if (VALIDATE_READ_DATA(skb, &icmp6h, l4_offset, sizeof(*icmp6h))) {
        return TC_ACT_UNSPEC;
    }
    if (icmp6h->icmp6_type != ICMPV6_NEIGHBOR_SOLICIT || icmp6h->icmp6_code != 0) {
        return TC_ACT_UNSPEC;
    }

    // The NS Target Address follows the 8-byte ICMPv6 header directly (the
    // 4-byte reserved field is part of the ICMPv6 header's data field).
    u8 target[16];
    if (bpf_skb_load_bytes(skb, l4_offset + sizeof(struct icmp6hdr), target, sizeof(target))) {
        return TC_ACT_UNSPEC;
    }

    // Only learn global / ULA unicast addresses
    if (is_unspecified_ip6(target) || is_multicast_ip6(target) || is_link_local_ip6(target)) {
        return TC_ACT_UNSPEC;
    }

    // DAD NS must be sent to the solicited-node multicast of the target
    // itself (RFC 4861), not to a different solicited-node address.
    if (!is_target_solicited_node(daddr, target)) return TC_ACT_UNSPEC;

    // Only learn targets inside subnets this interface directly serves: the
    // LPM lookup answers "is the target within an advertised LAN subnet".
    // The extra checks exclude (a) subnets routed to a downstream next-hop
    // (PD delegation) or WAN, (b) other interfaces' subnets, and (c) the
    // router's own address in the subnet (value.addr holds the sub_router for
    // Reachable entries), which must never be bound to a claimant's MAC.
    struct lan_route_key_v6 lan_key = {0};
    lan_key.prefixlen = 128;
    __builtin_memcpy(lan_key.addr.bytes, target, sizeof(target));
    struct lan_route_info_v6 *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &lan_key);
    union u_inet6_addr target_addr = {0};
    __builtin_memcpy(target_addr.bytes, target, sizeof(target));
    if (!lan_info || lan_info->route_type != ROUTE_TYPE_LAN ||
        lan_info->ifindex != skb->ingress_ifindex ||
        ip_addr_equal_in6(&lan_info->addr, &target_addr)) {
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0) return TC_ACT_UNSPEC;

    // Source link-layer address comes from the Ethernet header
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_UNSPEC;
    if (!is_target_solicited_node_mac(eth->h_dest, target)) return TC_ACT_UNSPEC;

    struct mac_key_v6 key = {0};
    __builtin_memcpy(key.addr.bytes, target, sizeof(target));

    struct mac_value_v6 value = {0};
    value.ifindex = skb->ingress_ifindex;
    value.proto = ETH_IPV6;
    __builtin_memcpy(value.mac, eth->h_source, 6);
    // dev_mac stays 0: it is never consumed by the redirect data path, and the
    // frame's destination MAC is the solicited-node multicast MAC, not ours.
    // sourced marks this entry as DAD-learned so the userspace reconcile does
    // not delete it (the kernel has no valid neigh entry for a DAD target).
    value.sourced = LD_MAC_SOURCE_DAD;

    // Only insert when no binding exists yet, so an authoritative binding
    // (neigh/FIB learning, userspace) is never overwritten by a DAD frame.
    if (bpf_map_update_elem(&ip_mac_v6, &key, &value, BPF_NOEXIST) == 0) {
        ld_bpf_log("learn DAD NS target: %pI6, ifindex: %d", target, value.ifindex);
        emit_ip6_dao_event(value.ifindex, target, eth->h_source);
    } else {
        // Already bound. Re-report whenever a *different* host now re-claims
        // the address, regardless of how the binding was learned (DAD, neigh,
        // or userspace): the original owner may be gone, or this is a
        // duplicate-address attempt, and userspace re-verifies liveness.
        // Same-host re-tests (the common benign case) never trigger an event.
        struct mac_value_v6 *existing = bpf_map_lookup_elem(&ip_mac_v6, &key);
        if (existing && !is_same_mac(existing->mac, eth->h_source)) {
            ld_bpf_log("re-claim DAD NS target: %pI6, ifindex: %d", target, value.ifindex);
            emit_ip6_dao_event(value.ifindex, target, eth->h_source);
        }
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}
