#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "chain/from_lan_root.h"
#include "neigh/neigh_ip4.h"

#include "chain/tc_wan_exit_maps.h"
#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct wan_egress_binding egress_binding = {};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

const volatile u32 current_l3_offset = 14;

static __always_inline __be32 wan_ipv4_next_hop(__be32 dst) {
    __be32 mask = egress_binding.wan_mask4;
    if ((dst & mask) != (egress_binding.wan_ip4 & mask)) return egress_binding.gateway_ip4;
    // Delegate a directed broadcast to the kernel. Both /31 endpoints are hosts.
    if (bpf_ntohl(mask) < 0xfffffffe && (dst | mask) == 0xffffffff) return 0;
    return dst;
}

/* A redirected frame carries the previous link's header. Same-device traffic
 * coming from the kernel already has its route's chosen next-hop header. */
static __always_inline int prepare_forwarded_ipv4(struct __sk_buff *skb) {
    if (!tc_cb_forwarded(skb) || is_host_direct(skb_mark(skb)) || !egress_binding.has_l2 ||
        egress_binding.is_pppoe)
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
    if (egress_binding.has_ipv4 && egress_binding.ifindex == skb->ifindex)
        next_hop = wan_ipv4_next_hop(dst);
    if (next_hop) {
        struct mac_key_v4 key = {.addr = next_hop};
        struct mac_value_v4 *entry = bpf_map_lookup_elem(&ip_mac_v4, &key);
        if (entry && entry->ifindex == skb->ifindex && !(entry->mac[0] & 1) &&
            !is_zero_mac(entry->mac)) {
            u8 src[6];
#pragma unroll
            for (int i = 0; i < 6; i++) src[i] = egress_binding.source_mac[i];
            if (!is_zero_mac(src)) {
                __builtin_memcpy(eth->h_dest, entry->mac, sizeof(eth->h_dest));
                __builtin_memcpy(eth->h_source, src, sizeof(eth->h_source));
                return TC_ACT_OK;
            }
        }
    }
    skb->cb[2] = TC_CB_NEIGH4_PENDING;
    skb->cb[3] = next_hop;
    skb->cb[4] = skb->ifindex;
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_wan_egress_root(struct __sk_buff *skb) {
    skb->cb[2] = 0;
    u8 l3_protocol = 0;
    if (current_l3_protocol(skb, current_l3_offset, &l3_protocol) == TC_ACT_OK) {
        if (l3_protocol == LANDSCAPE_IPV6_TYPE) {
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V6);
        } else {
            if (prepare_forwarded_ipv4(skb) == TC_ACT_SHOT) return TC_ACT_SHOT;
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V4);
        }
    }

    ld_from_wan_log("ROOT next-stage tail FAILED (l3 %u) -> exit", l3_protocol);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
