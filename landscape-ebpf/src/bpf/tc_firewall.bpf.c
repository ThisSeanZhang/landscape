#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/proto_def.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "firewall/firewall_share.h"
#include "reader/tc_fw4.h"
#include "reader/tc_fw6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline int fw_do_egress_v4(struct __sk_buff *skb) {
    struct tc_fw4_view view = {};
    if (!tc_fw4_read(skb, current_l3_offset, &view)) return TC_ACT_OK;

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = view.dst,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_egress_v6(struct __sk_buff *skb) {
    struct tc_fw6_view view = {};
    if (!tc_fw6_read(skb, current_l3_offset, &view)) return TC_ACT_OK;

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_search_key.addr, &view.dst, sizeof(block_search_key.addr));
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_ingress_v4(struct __sk_buff *skb) {
    struct tc_fw4_view view = {};
    if (!tc_fw4_read(skb, current_l3_offset, &view)) return TC_ACT_OK;

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = view.src,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_ingress_v6(struct __sk_buff *skb) {
    struct tc_fw6_view view = {};
    if (!tc_fw6_read(skb, current_l3_offset, &view)) return TC_ACT_OK;

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_search_key.addr, &view.src, sizeof(block_search_key.addr));
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_firewall_wan_egress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(fw_do_egress_v4(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/egress")
int tc_firewall_wan_egress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(fw_do_egress_v6(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/ingress")
int tc_firewall_wan_ingress_v4(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(fw_do_ingress_v4(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V4);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_firewall_wan_ingress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(fw_do_ingress_v6(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}
