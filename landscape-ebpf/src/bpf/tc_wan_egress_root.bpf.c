#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "chain/from_lan_root.h"
#include "neigh/neigh_ip4.h"

#include "chain/tc_from_lan_exit_maps.h"
#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct wan_egress_binding egress_binding = {};
/* Updated in place by this WAN's ARP worker. The first six bytes in memory
 * are the MAC in wire order. Zero means the gateway is unresolved. */
volatile __u64 confirmed_gateway_mac;
/* Updated in place by this WAN's NS worker; same layout as above. */
volatile __u64 confirmed_gateway_mac6;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

const volatile u32 current_l3_offset = 14;

static __always_inline __be32 wan_ipv4_next_hop(__be32 dst, __u64 *gateway_mac) {
    __be32 mask = egress_binding.wan_mask4;
    if ((dst & mask) != (egress_binding.wan_ip4 & mask)) {
        *gateway_mac = confirmed_gateway_mac;
        return egress_binding.gateway_ip4;
    }
    // Delegate a directed broadcast to the kernel. Both /31 endpoints are hosts.
    if (bpf_ntohl(mask) < 0xfffffffe && (dst | mask) == 0xffffffff) return 0;
    return dst;
}

/* A redirected frame carries the previous link's header. Same-device traffic
 * coming from the kernel already has its route's chosen next-hop header. */
static __always_inline int prepare_forwarded_ipv4(struct __sk_buff *skb) {
    if (!tc_cb_forwarded(skb) || !egress_binding.has_l2 || egress_binding.is_pppoe)
        return TC_ACT_OK;

    const u32 need = sizeof(struct ethhdr) + sizeof(struct iphdr);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + need > data_end) {
        if (bpf_skb_pull_data(skb, need)) return TC_ACT_SHOT;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        if (data + need > data_end) return TC_ACT_SHOT;
    }
    struct ethhdr *eth = data;
    const struct iphdr *iph = data + sizeof(*eth);
    __be32 dst = iph->daddr;
    if (is_broadcast_ip4(dst)) return TC_ACT_OK;

    __be32 next_hop = 0;
    __u64 gateway_mac = 0;
    if (egress_binding.has_ipv4 && egress_binding.ifindex == skb->ifindex)
        next_hop = wan_ipv4_next_hop(dst, &gateway_mac);
    if (next_hop) {
        const u8 *dmac = (const u8 *)&gateway_mac;
        if (!gateway_mac) {
            struct mac_key_v4 key = {.addr = next_hop};
            struct mac_value_v4 *entry = bpf_map_lookup_elem(&ip_mac_v4, &key);
            if (!entry || entry->ifindex != skb->ifindex || (entry->mac[0] & 1) ||
                is_zero_mac(entry->mac))
                goto pending;
            dmac = entry->mac;
        }
        u8 src[6];
#pragma unroll
        for (int i = 0; i < 6; i++) src[i] = egress_binding.source_mac[i];
        if (!is_zero_mac(src)) {
            __builtin_memcpy(eth->h_dest, dmac, sizeof(eth->h_dest));
            __builtin_memcpy(eth->h_source, src, sizeof(eth->h_source));
            return TC_ACT_OK;
        }
    }
pending:
    skb->cb[2] = TC_CB_NEIGH4_PENDING;
    skb->cb[3] = next_hop;
    skb->cb[4] = skb->ifindex;
    return TC_ACT_OK;
}

/* Off-link IPv6 leaves through the gateway probed by the NS worker; on-link
 * and unresolved frames keep the header prepared by the route stage. */
static __always_inline int prepare_forwarded_ipv6(struct __sk_buff *skb) {
    if (!tc_cb_forwarded(skb) || !egress_binding.has_l2 || egress_binding.is_pppoe ||
        !egress_binding.has_ipv6 || egress_binding.ifindex != skb->ifindex)
        return TC_ACT_OK;

    const u32 need = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + need > data_end) {
        if (bpf_skb_pull_data(skb, need)) return TC_ACT_SHOT;
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        if (data + need > data_end) return TC_ACT_SHOT;
    }
    struct ethhdr *eth = data;
    const struct ipv6hdr *ip6 = data + sizeof(*eth);
    const u8 *dst = ip6->daddr.in6_u.u6_addr8;
    if (unlikely((dst[0] & 0xff) == 0xff)) return TC_ACT_OK;

    u8 offlink = 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if ((dst[i] & egress_binding.wan_mask6[i]) !=
            (egress_binding.wan_ip6[i] & egress_binding.wan_mask6[i]))
            offlink = 1;
    }
    if (unlikely(!offlink)) return TC_ACT_OK;

    __u64 mac = confirmed_gateway_mac6;
    if (unlikely(!mac)) return TC_ACT_SHOT;
    __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
    // Byte loads keep clang from folding the const volatile source.
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_wan_egress_root(struct __sk_buff *skb) {
    skb->cb[2] = 0;

    /* Legacy HostDirect lanes skip the whole policy lineup; only the
     * chain exit (which may still PPPoE-encapsulate) runs. */
    if (is_skip_route_and_stage(skb_mark(skb))) goto exit;

    u8 l3_protocol = 0;
    if (current_l3_protocol(skb, current_l3_offset, &l3_protocol) == TC_ACT_OK) {
        if (l3_protocol == LANDSCAPE_IPV6_TYPE) {
            if (prepare_forwarded_ipv6(skb) == TC_ACT_SHOT) return TC_ACT_SHOT;
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V6);
        } else {
            if (prepare_forwarded_ipv4(skb) == TC_ACT_SHOT) return TC_ACT_SHOT;
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V4);
        }
    }

    ld_from_wan_log("ROOT next-stage tail FAILED (l3 %u) -> exit", l3_protocol);
exit:
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
