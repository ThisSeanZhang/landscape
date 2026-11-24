// SPDX-License-Identifier: GPL-2.0-or-later
/* Stateful NPTv6 (XDP NAT6) steady-state and miss micro-benchmarks.
 *
 * Aligned with bench_nat4_v4: each SEC("xdp") program runs single-shot under
 * kernel-side `repeat` batching. Packet headers in ctx->data are intentionally
 * kept read-only so all 256 repeats observe identical input addresses (avoiding
 * false prefix-migration slow paths on egress or no-op prefix short-circuits on
 * ingress), while `egress_steady` and `ingress_steady` still execute the full
 * NPTv6 prefix blend and L4 checksum delta math and prove the result via
 * `bench_sink`.
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "nat/xdp_nat6.h"
#include "reader/xdp_nat_read6.h"

#define BENCH_FAIL 0xdeadbeefULL

const volatile u32 current_ifindex = 6;
const volatile u32 current_l3_offset = sizeof(struct ethhdr);
const volatile __be64 expected_wan_prefix = 0;
const volatile __be64 expected_lan_prefix = 0;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bench_sink SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline void bench_sink_add(u64 value) {
    u32 index = 0;
    u64 *acc = bpf_map_lookup_elem(&bench_sink, &index);
    if (acc) *acc += value;
}

static __always_inline int bench_read6(struct xdp_md *ctx, __u8 direction,
                                       struct ip6_scan_offsets *off, struct in6_addr *src_addr,
                                       struct in6_addr *dst_addr, __be16 *sport, __be16 *dport,
                                       u64 *pkt_len) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end || eth->h_proto != ETH_IPV6) return 0;
    *pkt_len = (u64)(long)data_end - (u64)(long)data;

    if (xdp_nat_read6(ctx, current_l3_offset, direction, off, src_addr, dst_addr, sport, dport) !=
        XDP_NAT6_READ_OK)
        return 0;
    if (unlikely(should_nat_skip_protocol(xdp_nat6_outer_protocol(off)))) return 0;
    if (unlikely(!off->ports_valid)) return 0;
    return 1;
}

SEC("xdp")
int bench_nat6_baseline(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }
    bench_sink_add(1);
    return XDP_PASS;
}

SEC("xdp")
int bench_nat6_egress_steady(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(&off, &src_addr, sport, &dst_addr, dport, true, 0,
                                             current_ifindex, pkt_len, &trans)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }
    if (!trans.replace) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    __be64 old_prefix = 0;
    __builtin_memcpy(&old_prefix, src_addr.in6_u.u6_addr32, sizeof(old_prefix));
    __be64 new_prefix = (old_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

    u8 outer_proto = xdp_nat6_outer_protocol(&off);
    u32 l4_csum_off = 0;
    if (nat6_l4_checksum(off.l4_offset, outer_proto, &l4_csum_off)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __be16 *csum_ptr = data + l4_csum_off;
    if ((void *)(csum_ptr + 1) > data_end) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }
    __sum16 old_csum = *csum_ptr;
    __wsum delta = nat6_prefix_diff(old_prefix, new_prefix);
    __sum16 new_csum = nat6_apply_l4_checksum(old_csum, delta, outer_proto);

    bench_sink_add(new_prefix == expected_wan_prefix && new_csum != old_csum ? 1 : BENCH_FAIL);
    return XDP_PASS;
}

SEC("xdp")
int bench_nat6_egress_state_only(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    struct nat6_translation trans = {};
    int rc = !wan_ro_prefix6.b[0] ? NAT_OP_ERR
                                  : nat6_resolve(&off, &src_addr, sport, &dst_addr, dport, true, 0,
                                                 current_ifindex, pkt_len, &trans);
    bench_sink_add(rc == NAT_OP_OK && trans.replace && trans.client_prefix == expected_lan_prefix
                       ? 1
                       : BENCH_FAIL);
    return XDP_PASS;
}

SEC("xdp")
int bench_nat6_ingress_steady(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_WAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(&off, &dst_addr, dport, &src_addr, sport, false, 0,
                                             current_ifindex, pkt_len, &trans)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    __be64 old_prefix = 0;
    __builtin_memcpy(&old_prefix, dst_addr.in6_u.u6_addr32, sizeof(old_prefix));
    __be64 local_client_prefix = trans.client_prefix;
    if (!trans.replace || old_prefix == local_client_prefix) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    u8 outer_proto = xdp_nat6_outer_protocol(&off);
    u32 l4_csum_off = 0;
    if (nat6_l4_checksum(off.l4_offset, outer_proto, &l4_csum_off)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __be16 *csum_ptr = data + l4_csum_off;
    if ((void *)(csum_ptr + 1) > data_end) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }
    __sum16 old_csum = *csum_ptr;
    __wsum delta = nat6_prefix_diff(old_prefix, local_client_prefix);
    __sum16 new_csum = nat6_apply_l4_checksum(old_csum, delta, outer_proto);

    bench_sink_add(local_client_prefix == expected_lan_prefix && new_csum != old_csum ? 1
                                                                                      : BENCH_FAIL);
    return XDP_PASS;
}

SEC("xdp")
int bench_nat6_egress_miss(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_LAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    struct nat6_translation trans = {};
    int rc = nat6_resolve(&off, &src_addr, sport, &dst_addr, dport, true, 0, current_ifindex,
                          pkt_len, &trans);
    bench_sink_add(rc == NAT_OP_ERR ? 1 : BENCH_FAIL);
    return XDP_PASS;
}

SEC("xdp")
int bench_nat6_ingress_miss(struct xdp_md *ctx) {
    struct ip6_scan_offsets off = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};
    __be16 sport = 0;
    __be16 dport = 0;
    u64 pkt_len = 0;

    if (!bench_read6(ctx, LAND_FRAG_FROM_WAN, &off, &src_addr, &dst_addr, &sport, &dport,
                     &pkt_len)) {
        bench_sink_add(BENCH_FAIL);
        return XDP_PASS;
    }

    struct nat6_translation trans = {};
    int rc = nat6_resolve(&off, &dst_addr, dport, &src_addr, sport, false, 0, current_ifindex,
                          pkt_len, &trans);
    bench_sink_add(rc == NAT_OP_ERR ? 1 : BENCH_FAIL);
    return XDP_PASS;
}
