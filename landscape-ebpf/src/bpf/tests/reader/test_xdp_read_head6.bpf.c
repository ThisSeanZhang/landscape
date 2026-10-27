// SPDX-License-Identifier: GPL-2.0-or-later
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "reader/xdp_nat_read6.h"
#include "reader/xdp_nat_view.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;
const volatile u32 current_direction = LAND_FRAG_FROM_LAN;

struct xdp_reader_test_result {
    int read_ret;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __u16 l4_offset;
    __be16 sport;
    __be16 dport;
    __u16 icmp_inner_l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;
    __u8 frag_code;
    __u8 ports_valid;
    __u8 icmp_inner_l4_protocol;
    __u8 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct xdp_reader_test_result);
} xdp_reader_test_map SEC(".maps");

SEC("xdp")
int test_xdp_read_head6(struct xdp_md *ctx) {
    u32 key = 0;
    struct xdp_reader_test_result *r = bpf_map_lookup_elem(&xdp_reader_test_map, &key);
    if (!r) return XDP_PASS;

    __builtin_memset(r, 0, sizeof(*r));

    struct xdp_nat_view view = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    r->read_ret =
        xdp_nat_read6(ctx, &view, &src_addr, &dst_addr, current_l3_offset, (__u8)current_direction);
    r->src_addr = src_addr;
    r->dst_addr = dst_addr;
    r->l4_offset = view.l4_offset;
    r->sport = view.sport;
    r->dport = view.dport;
    r->icmp_inner_l4_offset = view.icmp_inner_l4_offset;
    r->l4_protocol = view.l4_protocol;
    r->tcp_phase = view.tcp_phase;
    r->frag_code = view.frag_code;
    r->ports_valid = view.ports_valid;
    r->icmp_inner_l4_protocol = view.icmp_inner_l4_protocol;
    return XDP_PASS;
}
