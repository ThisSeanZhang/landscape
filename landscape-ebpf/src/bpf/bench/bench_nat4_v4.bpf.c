// SPDX-License-Identifier: GPL-2.0-or-later
/* NAT4 v4 steady-state micro-benchmarks.
 *
 * The variants call the production TCP state phase directly. They do not
 * rewrite the packet, so the same input remains valid across kernel-side
 * repeat batching. Each successful run folds 1 into bench_sink; a failed
 * precheck or state lookup folds BENCH_FAIL so the Rust driver can prove
 * every repeat hit the intended path.
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "nat_v4/tc_nat4_packet.h"

#define BENCH_FAIL 0xdead

const volatile u32 current_l3_offset = 14;

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

static __always_inline int bench_read(struct __sk_buff *skb, struct tc_nat_view *view,
                                      __be32 *src_addr, __be32 *dst_addr, __u8 direction) {
    if (skb->protocol != bpf_htons(ETH_P_IP)) return 0;
    if (!tc_read_ipv4(skb, view, src_addr, dst_addr, current_l3_offset, direction)) return 0;
    if (view->l4_protocol != IPV4_PROTO_TCP) return 0;
    if (!view->ports_valid) return 0;
    return 1;
}

SEC("tc")
int bench_nat4_v4_baseline(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    if (!bench_read(skb, &view, &src_addr, &dst_addr, LAND_NAT_FRAG_FROM_LAN)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(1);
    return TC_ACT_OK;
}

SEC("tc")
int bench_nat4_v4_lan_steady(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (!bench_read(skb, &view, &src_addr, &dst_addr, LAND_NAT_FRAG_FROM_LAN)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = napt_lan_state(skb, &view, src_addr, dst_addr, &new_addr, &new_port);
    bench_sink_add(rc == TC_ACT_OK && new_port == bpf_htons(40000) ? 1 : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_nat4_v4_wan_steady(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (!bench_read(skb, &view, &src_addr, &dst_addr, LAND_NAT_FRAG_FROM_WAN)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (dst_addr != land_nat_external_addr) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = napt_wan_state(skb, &view, src_addr, dst_addr, &new_addr, &new_port);
    bench_sink_add(rc == TC_ACT_OK && new_port == bpf_htons(12345) ? 1 : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_nat4_v4_lan_miss(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (!bench_read(skb, &view, &src_addr, &dst_addr, LAND_NAT_FRAG_FROM_LAN)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = napt_lan_state(skb, &view, src_addr, dst_addr, &new_addr, &new_port);
    bench_sink_add(rc == TC_ACT_SHOT ? 1 : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_nat4_v4_wan_miss(struct __sk_buff *skb) {
    struct tc_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    __be32 new_addr = 0;
    __be16 new_port = 0;

    if (!bench_read(skb, &view, &src_addr, &dst_addr, LAND_NAT_FRAG_FROM_WAN)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (dst_addr != land_nat_external_addr) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = napt_wan_state(skb, &view, src_addr, dst_addr, &new_addr, &new_port);
    bench_sink_add(rc == TC_ACT_SHOT ? 1 : BENCH_FAIL);
    return TC_ACT_OK;
}
