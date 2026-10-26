#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "base/mark.h"
#include "chain/tc_stage.h"
#include "chain/tc_wan_exit_maps.h"
#include "nat/tc_nat6.h"
#include "reader/tc_nat_view.h"
#include "reader/tc_nat_read6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline int tc_nat_v6_egress_do(struct __sk_buff *skb, u32 ifindex) {
    struct tc_nat_view view = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    int ret = 0;

    if (!tc_nat_read6(skb, &view, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        return TC_ACT_OK;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&view)))) return TC_ACT_OK;
    if (unlikely(is_broadcast_ip6(src_addr.in6_u.u6_addr8) ||
                 is_broadcast_ip6(dst_addr.in6_u.u6_addr8)))
        return TC_ACT_OK;
    if (unlikely(!view.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_egress_prefix_check_and_replace(skb, &view, &src_addr, &dst_addr, current_l3_offset,
                                               ifindex);
    return ret == TC_ACT_SHOT ? TC_ACT_SHOT : TC_ACT_OK;
}

static __always_inline int tc_nat_v6_ingress_do(struct __sk_buff *skb, u32 ifindex) {
    struct tc_nat_view view = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    int ret = 0;

    if (!tc_nat_read6(skb, &view, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        return TC_ACT_OK;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&view)))) return TC_ACT_OK;
    if (unlikely(is_broadcast_ip6(src_addr.in6_u.u6_addr8) ||
                 is_broadcast_ip6(dst_addr.in6_u.u6_addr8)))
        return TC_ACT_OK;
    if (unlikely(!view.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_ingress_prefix_check_and_replace(skb, &view, &src_addr, &dst_addr, current_l3_offset,
                                                ifindex);
    return ret == TC_ACT_SHOT ? TC_ACT_SHOT : TC_ACT_OK;
}

static __always_inline int tc_nat_egress_v6_entry(struct __sk_buff *skb) {
    if (likely(current_l3_offset > 0)) {
        if (unlikely(is_broadcast_mac(skb) != TC_ACT_OK)) return TC_ACT_OK;
    }
    return tc_nat_v6_egress_do(skb, skb->ifindex);
}

static __always_inline int tc_nat_ingress_v6_entry(struct __sk_buff *skb) {
    if (likely(current_l3_offset > 0)) {
        if (unlikely(is_broadcast_mac(skb) != TC_ACT_OK)) return TC_ACT_OK;
    }
    return tc_nat_v6_ingress_do(skb, skb->ifindex);
}

SEC("tc/egress")
int tc_nat_wan_egress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(tc_nat_egress_v6_entry(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_LAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc/ingress")
int tc_nat_wan_ingress_v6(struct __sk_buff *skb) {
    if (likely(not_host_direct(skb_mark(skb)))) {
        if (unlikely(tc_nat_ingress_v6_entry(skb) == TC_ACT_SHOT)) return TC_ACT_SHOT;
    }

    TC_FROM_WAN_CHAIN_NEXT(skb, TC_SLOT_V6);
    TC_FROM_WAN_CHAIN_EXIT(skb);
    return TC_ACT_OK;
}
