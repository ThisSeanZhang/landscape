#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "nat/tc_nat6.h"
#include "base/landscape.h"
#include "reader/tc_nat_read6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int handle_ipv6_egress(struct __sk_buff *skb) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    int ret = 0;

    if (!tc_nat_read6(skb, current_l3_offset, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr,
                      &sport, &dport))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&off)))) return TC_ACT_OK;
    if (unlikely(!off.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_egress_prefix_check_and_replace(skb, &off, &src_addr, &dst_addr, sport, dport,
                                               skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}

SEC("tc/ingress")
int handle_ipv6_ingress(struct __sk_buff *skb) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    int ret = 0;

    if (!tc_nat_read6(skb, current_l3_offset, LAND_FRAG_FROM_WAN, &off, &src_addr, &dst_addr,
                      &sport, &dport))
        return TC_ACT_SHOT;

    if (unlikely(should_nat_skip_protocol(nat6_outer_protocol(&off)))) return TC_ACT_OK;
    if (unlikely(!off.ports_valid)) return TC_ACT_SHOT;

    ret = ipv6_ingress_prefix_check_and_replace(skb, &off, &src_addr, &dst_addr, sport, dport,
                                                skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
}
