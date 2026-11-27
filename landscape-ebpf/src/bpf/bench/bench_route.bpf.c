// SPDX-License-Identifier: GPL-2.0-or-later
/* Route data-plane micro-benchmarks (IPv4 and IPv6 LAN-to-WAN paths).
 *
 * Variants invoke the production functions from route4_path.h / route6_path.h
 * directly via single-shot SEC("tc") entrypoints under kernel-side `repeat`
 * batching:
 *
 * Tier 1 (stage-isolated lan_route):
 *  - baseline_v4 / baseline_v6:
 *      scan_route_packet + route4/6_read_context_from_scan + broadcast guard
 *  - lan_cache_hit_v4 / lan_cache_hit_v6:
 *      route4/6_search_cache_in_lan hitting LAN_CACHE (after a production
 *      WAN_CACHE miss), covering both L3/PPPoE targets (has_mac = 0) and
 *      Ethernet targets (has_mac = 1)
 *  - lan_cold_resolve_v4 / lan_cold_resolve_v6:
 *      route4/6_flow_verdict (match_flow_id MAC + IP LPM + flow_ip_map LPM +
 *      flow_dns_map LRU hash + priority arbitration) followed by
 *      bench_tc_route4/6_pick_wan (16-slot ECMP hash lookup)
 *  - lan_cold_full_v4 / lan_cold_full_v6:
 *      complete uncached LAN-ingress lookup sequence: cache search miss +
 *      rt4/6_lan_map LPM check miss + flow_verdict + slot pick (omitting
 *      cache insertion so every kernel-side repeat stays cold)
 *
 * Tier 2 (single BPF_PROG_TEST_RUN tail-call E2E: lan_route -> wan_egress_l2):
 *  - lan_cache_hit_v4_e2e / lan_cache_hit_v6_e2e:
 *      lan_route cache hit + tc_cb_mark_forwarded + tail-call into
 *      bench_wan_egress_l2_v4/6 replicating tc_wan_egress_root's
 *      prepare_forwarded_ipv4/6 (.rodata egress_binding + .bss gateway MAC
 *      rewrite and strict header/cb verification)
 *  - lan_cold_resolve_v4_e2e / lan_cold_resolve_v6_e2e:
 *      lan_route cold flow_verdict + slot pick + tail-call into
 *      bench_wan_egress_l2_v4/6
 *
 * Every entrypoint returns TC_ACT_OK so BPF_PROG_TEST_RUN never attempts a
 * live netdev redirect, while bench_sink accumulates the resolved flow_mark
 * (or BENCH_FAIL on any unexpected verdict) so Rust asserts every single run
 * took the exact expected branch.
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "chain/from_lan_root.h"
#include "chain/tc_cb.h"
#include "route/route4_context.h"
#include "route/route4_path.h"
#include "route/route6_context.h"
#include "route/route6_path.h"

#define BENCH_FAIL 0xdeadbeefULL
#define BENCH_EGRESS_SLOT_V4 0
#define BENCH_EGRESS_SLOT_V6 1

const volatile u32 current_l3_offset = 14;
const volatile struct wan_egress_binding egress_binding = {};
const volatile u8 expected_gw_mac4[6] = {};
const volatile u8 expected_gw_mac6[6] = {};

/* Updated from userspace before Tier-2 runs; matches tc_wan_egress_root.bpf.c
 * layout (first six bytes in memory are the MAC in wire order). */
volatile __u64 confirmed_gateway_mac;
volatile __u64 confirmed_gateway_mac6;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} bench_sink SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} bench_egress_chain SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline void bench_sink_add(u64 value) {
    u32 index = 0;
    u64 *acc = bpf_map_lookup_elem(&bench_sink, &index);
    if (acc) *acc += value;
}

static __always_inline int bench_read4(struct __sk_buff *skb, struct route4_context *context) {
    struct route_view view = {0};
    if (scan_route_packet(skb, current_l3_offset, &view) != TC_ACT_OK) return 0;
    if (route4_read_context_from_scan(skb, &view, context) != TC_ACT_OK) return 0;
    if (unlikely(is_broadcast_ip4(context->daddr))) return 0;
    return 1;
}

static __always_inline int bench_read6(struct __sk_buff *skb, struct route6_context *context) {
    struct route_view view = {0};
    if (scan_route_packet(skb, current_l3_offset, &view) != TC_ACT_OK) return 0;
    if (route6_read_context_from_scan(skb, &view, context) != TC_ACT_OK) return 0;
    if (unlikely(is_broadcast_ip6(context->daddr.in6_u.u6_addr8))) return 0;
    return 1;
}

/* Equivalent to tc_route4_pick_wan_in_lan in tc_lan_ingress_route.bpf.c. */
static __always_inline int bench_tc_route4_pick_wan(struct __sk_buff *skb, u32 l3_offset,
                                                    const struct route4_context *context,
                                                    const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route4_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route4_target_slot(context->daddr),
    };
    struct route4_target_info *target_info = bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
    if (target_info == NULL) return TC_ACT_SHOT;

    if (target_info->ifindex != skb->ingress_ifindex) {
        if (l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac(skb, target_info->is_docker) != 0) return TC_ACT_SHOT;
        }
        if (target_info->is_docker) {
            bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            return bpf_redirect(target_info->ifindex, 0);
        }
    }

    tc_cb_mark_forwarded(skb, target_info->link_chain_id);
    return bpf_redirect(target_info->ifindex, 0);
}

/* Equivalent to tc_route6_pick_wan_in_lan in tc_lan_ingress_route.bpf.c. */
static __always_inline int bench_tc_route6_pick_wan(struct __sk_buff *skb, u32 l3_offset,
                                                    const struct route6_context *context,
                                                    const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route6_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route6_target_slot(&context->daddr),
    };
    struct route6_target_info *target_info = bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
    if (target_info == NULL) return TC_ACT_SHOT;

    if (target_info->ifindex != skb->ingress_ifindex) {
        if (l3_offset == 0 && target_info->has_mac) {
            if (prepend_dummy_mac_v6(skb) != 0) return TC_ACT_SHOT;
        }
        if (target_info->is_docker) {
            bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
            return bpf_redirect(target_info->ifindex, 0);
        }
    }

    tc_cb_mark_forwarded(skb, target_info->link_chain_id);
    return bpf_redirect(target_info->ifindex, 0);
}

static __always_inline __be32 bench_wan_ipv4_next_hop(__be32 dst, __u64 *gateway_mac) {
    __be32 mask = egress_binding.wan_mask4;
    if ((dst & mask) != (egress_binding.wan_ip4 & mask)) {
        *gateway_mac = confirmed_gateway_mac;
        return egress_binding.gateway_ip4;
    }
    if (bpf_ntohl(mask) < 0xfffffffe && (dst | mask) == 0xffffffff) return 0;
    return dst;
}

/* Replicates prepare_forwarded_ipv4 from tc_wan_egress_root.bpf.c. */
static __always_inline int bench_prepare_forwarded_ipv4(struct __sk_buff *skb) {
    if (!tc_cb_forwarded(skb) || !egress_binding.has_l2 || egress_binding.is_pppoe)
        return TC_ACT_OK;

    const u32 need = sizeof(struct ethhdr) + sizeof(struct iphdr);
    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    barrier_var(data);
    if (data + need > data_end) {
        if (bpf_skb_pull_data(skb, need)) return TC_ACT_SHOT;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        barrier_var(data);
        if (data + need > data_end) return TC_ACT_SHOT;
    }
    struct ethhdr *eth = (struct ethhdr *)data;
    const struct iphdr *iph = (const struct iphdr *)(data + sizeof(*eth));
    __be32 dst = iph->daddr;
    if (is_broadcast_ip4(dst)) return TC_ACT_OK;

    __be32 next_hop = 0;
    __u64 gateway_mac = 0;
    if (egress_binding.has_ipv4 && egress_binding.ifindex == skb->ifindex)
        next_hop = bench_wan_ipv4_next_hop(dst, &gateway_mac);
    if (next_hop) {
        const u8 *dmac = (const u8 *)&gateway_mac;
        if (!gateway_mac) {
            struct mac_key_v4 key = {.addr = next_hop};
            struct mac_value_v4 *entry = bpf_map_lookup_elem(&ip_mac_v4, &key);
            if (!entry || entry->ifindex != skb->ifindex || (entry->mac[0] & 1) ||
                is_zero_mac(entry->mac))
                goto pending;
            dmac = entry->mac;
        }
        u8 src[6];
#pragma unroll
        for (int i = 0; i < 6; i++) src[i] = egress_binding.source_mac[i];
        if (!is_zero_mac(src)) {
            __builtin_memcpy(eth->h_dest, dmac, sizeof(eth->h_dest));
            __builtin_memcpy(eth->h_source, src, sizeof(eth->h_source));
            return TC_ACT_OK;
        }
    }
pending:
    skb->cb[2] = TC_CB_NEIGH4_PENDING;
    skb->cb[3] = next_hop;
    skb->cb[4] = skb->ifindex;
    return TC_ACT_OK;
}

/* Replicates prepare_forwarded_ipv6 from tc_wan_egress_root.bpf.c. */
static __always_inline int bench_prepare_forwarded_ipv6(struct __sk_buff *skb) {
    if (!tc_cb_forwarded(skb) || !egress_binding.has_l2 || egress_binding.is_pppoe ||
        !egress_binding.has_ipv6 || egress_binding.ifindex != skb->ifindex)
        return TC_ACT_OK;

    const u32 need = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    barrier_var(data);
    if (data + need > data_end) {
        if (bpf_skb_pull_data(skb, need)) return TC_ACT_SHOT;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        barrier_var(data);
        if (data + need > data_end) return TC_ACT_SHOT;
    }
    struct ethhdr *eth = (struct ethhdr *)data;
    const struct ipv6hdr *ip6 = (const struct ipv6hdr *)(data + sizeof(*eth));
    const u8 *dst = ip6->daddr.in6_u.u6_addr8;
    if (unlikely((dst[0] & 0xff) == 0xff)) return TC_ACT_OK;

    __u64 mac = confirmed_gateway_mac6;
    if (unlikely(!mac)) return TC_ACT_SHOT;
    __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
    return TC_ACT_OK;
}

static __always_inline bool bench_mac_eq_ro(const u8 mac[6], const volatile u8 expected[6]) {
    bool eq = true;
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (mac[i] != expected[i]) eq = false;
    }
    return eq;
}

/* -- Tier-2 WAN egress L2 tail-call targets ------------------------------- */

SEC("tc")
int bench_wan_egress_l2_v4(struct __sk_buff *skb) {
    skb->cb[2] = 0;

    u32 flow_mark = skb_mark(skb);
    if (unlikely(is_skip_route_and_stage(flow_mark) || skb->protocol != ETH_IPV4 ||
                 flow_mark == 0 || !tc_cb_forwarded(skb) || tc_cb_chain(skb) == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    int rc = bench_prepare_forwarded_ipv4(skb);
    if (unlikely(rc == TC_ACT_SHOT || skb->cb[2] == TC_CB_NEIGH4_PENDING)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    barrier_var(data);
    if (unlikely(data + sizeof(struct ethhdr) > data_end)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    const struct ethhdr *eth = (const struct ethhdr *)data;
    bool ok = bench_mac_eq_ro(eth->h_dest, expected_gw_mac4) &&
              bench_mac_eq_ro(eth->h_source, egress_binding.source_mac);

    /* Reset per-run control state so every repeat must re-stamp cb and mark. */
    skb->cb[0] = 0;
    skb_set_mark(skb, 0);
    bench_sink_add(ok ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_wan_egress_l2_v6(struct __sk_buff *skb) {
    skb->cb[2] = 0;

    u32 flow_mark = skb_mark(skb);
    if (unlikely(is_skip_route_and_stage(flow_mark) || skb->protocol != ETH_IPV6 ||
                 flow_mark == 0 || !tc_cb_forwarded(skb) || tc_cb_chain(skb) == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    int rc = bench_prepare_forwarded_ipv6(skb);
    if (unlikely(rc == TC_ACT_SHOT || skb->cb[2] == TC_CB_NEIGH4_PENDING)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    barrier_var(data);
    if (unlikely(data + sizeof(struct ethhdr) > data_end)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    const struct ethhdr *eth = (const struct ethhdr *)data;
    bool ok = bench_mac_eq_ro(eth->h_dest, expected_gw_mac6) &&
              bench_mac_eq_ro(eth->h_source, egress_binding.source_mac);

    /* Reset per-run control state so every repeat must re-stamp cb and mark. */
    skb->cb[0] = 0;
    skb_set_mark(skb, 0);
    bench_sink_add(ok ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

/* -- IPv4 benchmarks (Tier-1 + Tier-2 E2E) -------------------------------- */

SEC("tc")
int bench_route4_baseline(struct __sk_buff *skb) {
    struct route4_context context = {0};

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(1);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cache_hit(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cold_resolve(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route4_pick_wan(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cold_full(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (tc_route4_lan_redirect_check_in_lan(skb, current_l3_offset, &context) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route4_pick_wan(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cache_hit_e2e(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route4_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    if (unlikely(rc != TC_ACT_REDIRECT || flow_mark == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    skb_set_mark(skb, flow_mark);
    bpf_tail_call_static(skb, &bench_egress_chain, BENCH_EGRESS_SLOT_V4);
    bench_sink_add(BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route4_lan_cold_resolve_e2e(struct __sk_buff *skb) {
    struct route4_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read4(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route4_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route4_pick_wan(skb, current_l3_offset, &context, flow_mark);
    if (unlikely(rc != TC_ACT_REDIRECT || flow_mark == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    skb_set_mark(skb, flow_mark);
    bpf_tail_call_static(skb, &bench_egress_chain, BENCH_EGRESS_SLOT_V4);
    bench_sink_add(BENCH_FAIL);
    return TC_ACT_OK;
}

/* -- IPv6 benchmarks (Tier-1 + Tier-2 E2E) -------------------------------- */

SEC("tc")
int bench_route6_baseline(struct __sk_buff *skb) {
    struct route6_context context = {0};

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    bench_sink_add(1);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cache_hit(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cold_resolve(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route6_pick_wan(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cold_full(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (tc_route6_lan_redirect_check_in_lan(skb, current_l3_offset, &context) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route6_pick_wan(skb, current_l3_offset, &context, flow_mark);
    bench_sink_add(rc == TC_ACT_REDIRECT && flow_mark != 0 ? (u64)flow_mark : BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cache_hit_e2e(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
    if (unlikely(rc != TC_ACT_REDIRECT || flow_mark == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    skb_set_mark(skb, flow_mark);
    bpf_tail_call_static(skb, &bench_egress_chain, BENCH_EGRESS_SLOT_V6);
    bench_sink_add(BENCH_FAIL);
    return TC_ACT_OK;
}

SEC("tc")
int bench_route6_lan_cold_resolve_e2e(struct __sk_buff *skb) {
    struct route6_context context = {0};
    u32 flow_mark = 0;

    if (!bench_read6(skb, &context)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    if (route6_flow_verdict(skb, current_l3_offset, &context, &flow_mark) != TC_ACT_OK) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    int rc = bench_tc_route6_pick_wan(skb, current_l3_offset, &context, flow_mark);
    if (unlikely(rc != TC_ACT_REDIRECT || flow_mark == 0)) {
        bench_sink_add(BENCH_FAIL);
        return TC_ACT_OK;
    }
    skb_set_mark(skb, flow_mark);
    bpf_tail_call_static(skb, &bench_egress_chain, BENCH_EGRESS_SLOT_V6);
    bench_sink_add(BENCH_FAIL);
    return TC_ACT_OK;
}
