#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/proto_def.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "firewall/firewall_share.h"
#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "reader/tc_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline bool fw_frag_single(u8 frag_code) {
    return frag_code == LAND_NAT_FRAG_NONE || frag_code == TC_CB_FRAG_SINGLE_V6H;
}

static __always_inline int fw_do_egress_v4(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        return TC_ACT_OK;

    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return TC_ACT_SHOT;

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = dst_addr,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_egress_v6(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    if (!tc_read_ipv6(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        return TC_ACT_OK;

    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return TC_ACT_SHOT;

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_search_key.addr, &dst_addr, sizeof(block_search_key.addr));
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip6_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_ingress_v4(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    if (!tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        return TC_ACT_OK;

    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return TC_ACT_SHOT;

    struct ipv4_lpm_key block_search_key = {
        .prefixlen = 32,
        .addr = src_addr,
    };
    if (unlikely(bpf_map_lookup_elem(&firewall_block_ip4_map, &block_search_key)))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static __always_inline int fw_do_ingress_v6(struct __sk_buff *skb) {
    struct skb_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    if (!tc_read_ipv6(skb, &cb, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        return TC_ACT_OK;

    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return TC_ACT_SHOT;

    struct ipv6_lpm_key block_search_key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&block_search_key.addr, &src_addr, sizeof(block_search_key.addr));
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
