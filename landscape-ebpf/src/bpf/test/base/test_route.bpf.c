#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "route/route4_path.h"
#include "route/route6_path.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline int read_route6_context(struct __sk_buff *skb,
                                               struct route6_context *context) {
    struct ipv6hdr *ip6h;

    if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(struct ipv6hdr))) {
        return TC_ACT_SHOT;
    }

    COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    context->l4_protocol = ip6h->nexthdr;

    return TC_ACT_OK;
}

static __always_inline int read_route4_context(struct __sk_buff *skb,
                                               struct route4_context *context) {
    struct iphdr *iph;

    if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(struct iphdr))) {
        return TC_ACT_SHOT;
    }

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    context->l4_protocol = iph->protocol;

    return TC_ACT_OK;
}

SEC("tc")
int test_route_v6_search_cache_in_lan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route_v6_search_cache_in_lan"
    struct route6_context context = {0};
    u32 flow_mark = skb->mark;
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return route6_search_cache_in_lan(skb, current_l3_offset, &context, &flow_mark);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route_v6_set_cache_in_wan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route_v6_set_cache_in_wan"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return route6_set_cache_in_wan(&context, current_l3_offset, skb->ifindex);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_pick_wan_by_flow_id_default(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_pick_wan_by_flow_id_default"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    struct route6_slot_key slot_key = {
        .flow_id = 0,
        .slot = (((u32)context.saddr.all[0]) ^ ((u32)context.saddr.all[1]) ^
                 (((u32)context.daddr.all[0]) << 1) ^ (((u32)context.daddr.all[1]) << 2) ^
                 ((u32)context.daddr.all[2]) ^ (((u32)context.daddr.all[3]) << 1) ^
                 (((u32)context.l4_protocol) << 24)) &
                0xF,
    };
    struct route6_target_info *target_info = bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
    if (target_info == NULL) {
        return TC_ACT_UNSPEC;
    }
    return (int)target_info->ifindex;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_pick_wan_by_flow_id_non_default(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_pick_wan_by_flow_id_non_default"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    struct route6_slot_key slot_key = {
        .flow_id = 5,
        .slot = (((u32)context.saddr.all[0]) ^ ((u32)context.saddr.all[1]) ^
                 (((u32)context.daddr.all[0]) << 1) ^ (((u32)context.daddr.all[1]) << 2) ^
                 ((u32)context.daddr.all[2]) ^ (((u32)context.daddr.all[3]) << 1) ^
                 (((u32)context.l4_protocol) << 24)) &
                0xF,
    };
    struct route6_target_info *target_info = bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
    if (target_info == NULL) {
        return TC_ACT_SHOT;
    }
    return (int)target_info->ifindex;
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_cached_docker_vlan_id(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_cached_docker_vlan_id"
    struct route6_cache_value target = {0};
    target.mark_value = 0x0305;

    return route_flow_mark_vlan_id(target.mark_value);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_cached_docker_redirect(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_cached_docker_redirect"
    struct route6_cache_value target = {0};
    target.mark_value = 0x0305;

    int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, route_flow_mark_vlan_id(target.mark_value));
    if (ret) {
        return ret;
    }

    return skb->vlan_tci;
#undef BPF_LOG_TOPIC
}

// ── lan_redirect_check unit hooks: each wraps one of the three per-hook
//    lan_redirect_check implementations so tests can lock their behaviour
//    before any dedup refactor. F1 (in_wan) is always invoked with
//    is_lan = false, matching its only production caller. ──

SEC("tc")
int test_route4_lan_redirect_check_in_wan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route4_lan_redirect_check_in_wan"
    struct route4_context context = {0};
    int ret = read_route4_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route4_lan_redirect_check_in_wan(skb, current_l3_offset, &context, false);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route4_lan_redirect_check_in_lan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route4_lan_redirect_check_in_lan"
    struct route4_context context = {0};
    int ret = read_route4_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route4_lan_redirect_check_in_lan(skb, current_l3_offset, &context);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route4_lan_redirect_check_in_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route4_lan_redirect_check_in_wan_egress"
    struct route4_context context = {0};
    int ret = read_route4_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route4_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
#undef BPF_LOG_TOPIC
}
SEC("tc")
int test_route6_lan_redirect_check_in_wan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_lan_redirect_check_in_wan"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route6_lan_redirect_check_in_wan(skb, current_l3_offset, &context, false);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_lan_redirect_check_in_lan(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_lan_redirect_check_in_lan"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route6_lan_redirect_check_in_lan(skb, current_l3_offset, &context);
#undef BPF_LOG_TOPIC
}

SEC("tc")
int test_route6_lan_redirect_check_in_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route6_lan_redirect_check_in_wan_egress"
    struct route6_context context = {0};
    int ret = read_route6_context(skb, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return tc_route6_lan_redirect_check_in_wan_egress(skb, current_l3_offset, &context);
#undef BPF_LOG_TOPIC
}
