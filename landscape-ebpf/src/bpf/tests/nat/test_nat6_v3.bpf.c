#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nat/tc_nat6.h"
#include "base/landscape.h"
#include "reader/tc_nat_view.h"
#include "reader/tc_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int handle_ipv6_egress(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    int ret = 0;

    if (!tc_read_ipv6(skb, &view, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_LAN))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&view)))) return TC_ACT_OK;
    if (unlikely(!view.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_egress_prefix_check_and_replace(skb, &view, &src_addr, &dst_addr, current_l3_offset,
                                               skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}

SEC("tc/ingress")
int handle_ipv6_ingress(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    int ret = 0;

    if (!tc_read_ipv6(skb, &view, &src_addr, &dst_addr, current_l3_offset, LAND_NAT_FRAG_FROM_WAN))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&view)))) return TC_ACT_OK;
    if (unlikely(!view.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_ingress_prefix_check_and_replace(skb, &view, &src_addr, &dst_addr, current_l3_offset,
                                                skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}
