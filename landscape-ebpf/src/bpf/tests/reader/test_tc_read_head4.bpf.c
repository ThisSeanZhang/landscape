// SPDX-License-Identifier: GPL-2.0-or-later
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "reader/tc_nat_view.h"
#include "reader/tc_read_head4.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;
const volatile u32 current_direction = LAND_NAT_FRAG_FROM_LAN;

struct reader_test_result {
    int read_ret;
    __be32 src_addr;
    __be32 dst_addr;
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
int test_tc_read_head4(struct __sk_buff *skb) {
    u32 key = 0;
    struct reader_test_result *r = bpf_map_lookup_elem(&reader_test_map, &key);
    if (!r) return 0;

    __builtin_memset(r, 0, sizeof(*r));

    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    r->read_ret =
        tc_read_ipv4(skb, &view, &src_addr, &dst_addr, current_l3_offset, (__u8)current_direction);
    r->src_addr = src_addr;
    r->dst_addr = dst_addr;
    r->l3_offset = view.l3_offset;
    r->l4_offset = view.l4_offset;
    r->sport = view.sport;
    r->dport = view.dport;
    r->icmp_inner_l4_offset = view.icmp_inner_l4_offset;
    r->l4_protocol = view.l4_protocol;
    r->tcp_phase = view.tcp_phase;
    r->frag_code = view.frag_code;
    r->ports_valid = view.ports_valid;
    r->icmp_inner_l4_protocol = view.icmp_inner_l4_protocol;
    return 0;
}
