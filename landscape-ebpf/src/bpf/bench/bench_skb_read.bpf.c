// TC-path packet-read micro-benchmarks, driven by src/bench/skb_read.rs
// (methodology there: kernel-side `repeat` batching, baseline subtraction,
// interleaved sampling). Each run folds a deterministic value into
// bench_sink; ARRAY values survive across BPF_PROG_TEST_RUN repeats, so
// userspace can assert runs * per_run_value — proof every run did the
// read. TEST_RUN hands the programs a linear skb, so VALIDATE_READ_DATA
// always takes the fast path and never pulls.

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "base/proto_def.h"
#include "scanner/skb_common.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"

#define BENCH_FAIL 0xdead

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bench_sink SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/* iphdr.saddr..daddr and ipv6hdr.saddr..daddr are contiguous, so each
 * variant reads the same bytes it folds into the sink. */
struct bench_v4_addrs {
    __be32 saddr;
    __be32 daddr;
};

struct bench_v6_addrs {
    union u_inet6_addr saddr;
    union u_inet6_addr daddr;
};

/* ARRAY values survive across BPF_PROG_TEST_RUN repeats: accumulate one
 * deterministic value per run so userspace can prove every run read. */
static __always_inline void bench_sink_add(u64 val) {
    u32 zero = 0;
    u64 *acc = bpf_map_lookup_elem(&bench_sink, &zero);
    if (acc) *acc += val;
}

static __always_inline int bench_eth_is(struct __sk_buff *skb, __be16 want) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return 0;
    return eth->h_proto == want;
}

SEC("tc")
int bench_tc_baseline(struct __sk_buff *skb) {
    /* Same shape as the variants: one ethertype check, one sink fold. */
    if (!bench_eth_is(skb, ETH_IPV4) && !bench_eth_is(skb, ETH_IPV6)) return TC_ACT_OK;
    bench_sink_add(1);
    return TC_ACT_OK;
}

/* One VALIDATE_READ_DATA (fast path) + two 32-bit loads. */
SEC("tc")
int bench_tc_direct4(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV4)) return TC_ACT_OK;

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add((u64)(u32)iph->saddr + (u64)(u32)iph->daddr);
    return TC_ACT_OK;
}

/* Same 8 bytes, but through one bpf_skb_load_bytes helper call. */
SEC("tc")
int bench_tc_helper4(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV4)) return TC_ACT_OK;

    struct bench_v4_addrs addrs;
    if (bpf_skb_load_bytes(skb, current_l3_offset + offsetof(struct iphdr, saddr), &addrs,
                           sizeof(addrs))) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add((u64)(u32)addrs.saddr + (u64)(u32)addrs.daddr);
    return TC_ACT_OK;
}

/* One VALIDATE_READ_DATA + eight 32-bit loads. */
SEC("tc")
int bench_tc_direct6(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV6)) return TC_ACT_OK;

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    u64 acc = 0;
    for (int j = 0; j < 4; j++) {
        acc += (u64)(u32)ip6h->saddr.in6_u.u6_addr32[j];
        acc += (u64)(u32)ip6h->daddr.in6_u.u6_addr32[j];
    }
    bench_sink_add(acc);
    return TC_ACT_OK;
}

/* Same 32 bytes, but through one bpf_skb_load_bytes helper call. */
SEC("tc")
int bench_tc_helper6(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV6)) return TC_ACT_OK;

    struct bench_v6_addrs addrs;
    if (bpf_skb_load_bytes(skb, current_l3_offset + offsetof(struct ipv6hdr, saddr), &addrs,
                           sizeof(addrs))) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    u64 acc = 0;
    for (int j = 0; j < 4; j++) {
        acc += (u64)(u32)addrs.saddr.all[j];
        acc += (u64)(u32)addrs.daddr.all[j];
    }
    bench_sink_add(acc);
    return TC_ACT_OK;
}

/* One complete L3+L4 scan of a plain TCP packet (l4_offset + l4_protocol;
 * every other idx field stays 0: 34 + 6 for v4, 54 + 6 for v6). */
SEC("tc")
int bench_tc_scan4_full(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV4)) return TC_ACT_OK;

    struct scan_ipv4_idx idx = {};
    if (scan_ipv4_full(skb, current_l3_offset, &idx)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(idx.l4_offset + idx.l4_protocol + idx.fragment_type + idx.fragment_off +
                   idx.fragment_id + idx.pkt_type + idx.icmp_error_l3_offset +
                   idx.icmp_error_inner_l4_offset + idx.icmp_error_l4_protocol);
    return TC_ACT_OK;
}

SEC("tc")
int bench_tc_scan6_full(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV6)) return TC_ACT_OK;

    struct scan_ipv6_idx idx = {};
    if (scan_ipv6_full(skb, current_l3_offset, &idx)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(idx.l4_offset + idx.l4_protocol + idx.fragment_type + idx.fragment_off +
                   idx.fragment_id + idx.pkt_type + idx.icmp_error_l3_offset +
                   idx.icmp_error_inner_l4_offset + idx.icmp_error_l4_protocol);
    return TC_ACT_OK;
}

/* Two-stage read per run: scan_ipv4_into_idx then skb_read_ipv4_info
 * (address pair + ports off the scanned idx) — the production
 * "packet -> flow pair" flow. */
SEC("tc")
int bench_tc_read4_info(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV4)) return TC_ACT_OK;

    struct scan_ipv4_idx idx = {};
    if (scan_ipv4_into_idx(skb, current_l3_offset, &idx)) return TC_ACT_OK;

    struct inet4_pair pair = {};
    if (skb_read_ipv4_info(skb, current_l3_offset, &idx, &pair)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add((u64)(u32)pair.src_addr.addr + (u64)(u32)pair.dst_addr.addr +
                   bpf_ntohs(pair.src_port) + bpf_ntohs(pair.dst_port));
    return TC_ACT_OK;
}

/* Deepest production read: the full scan (ICMP error classification +
 * embedded inner IP header walk + outer-daddr/inner-saddr cross-check)
 * followed by skb_read_ipv4_info, which re-reads the outer addresses,
 * the inner daddr and the embedded inner L4 ports off the idx. */
SEC("tc")
int bench_tc_read4_icmp(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV4)) return TC_ACT_OK;

    struct scan_ipv4_idx idx = {};
    if (scan_ipv4_full(skb, current_l3_offset, &idx)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    struct inet4_pair pair = {};
    if (skb_read_ipv4_info(skb, current_l3_offset, &idx, &pair)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add((u64)(u32)pair.src_addr.addr + (u64)(u32)pair.dst_addr.addr +
                   bpf_ntohs(pair.src_port) + bpf_ntohs(pair.dst_port));
    return TC_ACT_OK;
}

/* v6 twin of bench_tc_read4_icmp: scan_ipv6_full + skb_read_ipv6_info on
 * an ICMPv6 error with an embedded inner IPv6 header + L4 quote. */
SEC("tc")
int bench_tc_read6_icmp(struct __sk_buff *skb) {
    if (!bench_eth_is(skb, ETH_IPV6)) return TC_ACT_OK;

    struct scan_ipv6_idx idx = {};
    if (scan_ipv6_full(skb, current_l3_offset, &idx)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    struct inet_pair pair = {};
    if (skb_read_ipv6_info(skb, current_l3_offset, &idx, &pair)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    u64 acc = 0;
    for (int j = 0; j < 4; j++) {
        acc += (u64)(u32)pair.src_addr.all[j];
        acc += (u64)(u32)pair.dst_addr.all[j];
    }
    bench_sink_add(acc + bpf_ntohs(pair.src_port) + bpf_ntohs(pair.dst_port));
    return TC_ACT_OK;
}
