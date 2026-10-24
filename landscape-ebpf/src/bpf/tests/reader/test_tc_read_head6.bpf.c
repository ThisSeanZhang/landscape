// SPDX-License-Identifier: GPL-2.0-or-later
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;
const volatile u32 current_direction = LAND_NAT_FRAG_FROM_LAN;

struct reader_test_result {
    int read_ret;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __u16 l3_offset;
    __u16 l4_offset;
    __u16 sport;
    __u16 dport;
    __u16 icmp_inner_l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;
    __u8 frag_code;
    __u8 ports_valid;
    __u8 icmp_inner_l4_protocol;
    __u8 _pad[1];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct reader_test_result);
} reader_test_map SEC(".maps");

SEC("tc/ingress")
int test_tc_read_head6(struct __sk_buff *skb) {
    u32 key = 0;
    struct reader_test_result *r = bpf_map_lookup_elem(&reader_test_map, &key);
    if (!r) return 0;

    __builtin_memset(r, 0, sizeof(*r));

    struct skb_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    r->read_ret =
        tc_read_ipv6(skb, &cb, &src_addr, &dst_addr, current_l3_offset, (__u8)current_direction);
    r->src_addr = src_addr;
    r->dst_addr = dst_addr;
    r->l3_offset = cb.l3_offset;
    r->l4_offset = cb.l4_offset;
    r->sport = cb.sport;
    r->dport = cb.dport;
    r->icmp_inner_l4_offset = cb.icmp_inner_l4_offset;
    r->l4_protocol = cb.l4_protocol;
    r->tcp_phase = cb.tcp_phase;
    r->frag_code = cb.frag_code;
    r->ports_valid = cb.ports_valid;
    r->icmp_inner_l4_protocol = cb.icmp_inner_l4_protocol;
    return 0;
}
