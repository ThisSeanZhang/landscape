#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "route/route4_path.h"
#include "route/route6_path.h"
#include "route/route4_context.h"
#include "route/route6_context.h"

#include "chain/tc_cb.h"
#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline u8 get_wan_ingress_l3_offset(struct __sk_buff *skb) {
    return skb->cb[TC_CHAIN_CB_L3_OFFSET];
}

#undef BPF_LOG_TOPIC

#define TC_INGRESS_V4_SLOT 0
#define TC_INGRESS_V6_SLOT 1

SEC("tc/ingress")
int tc_wan_ingress_route_v4(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_wan_ingress_route_v4"
    int ret = 0;
    struct route4_context context = {0};
    struct packet_offset_info offset_info = {0};
    u8 l3 = get_wan_ingress_l3_offset(skb);

    ret = scan_route_packet(skb, l3, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route4_read_context_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip4(context.daddr))) {
        return TC_ACT_UNSPEC;
    }

    ret = route4_is_current_wan_packet(skb, l3, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = tc_route4_lan_redirect_check_in_wan(skb, l3, &context, false);
    if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            route4_set_cache_in_wan(&context, l3, skb->ifindex);
        }
    }

    return ret == TC_ACT_OK ? TC_ACT_OK : ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_wan_ingress_route_v6(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_wan_ingress_route_v6"
    int ret = 0;
    struct route6_context context = {0};
    struct packet_offset_info offset_info = {0};
    u8 l3 = get_wan_ingress_l3_offset(skb);

    ret = scan_route_packet(skb, l3, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route6_read_context_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    if (unlikely(is_broadcast_ip6(context.daddr.bytes))) {
        return TC_ACT_UNSPEC;
    }

    ret = route6_is_current_wan_packet(skb, l3, &context);
    if (ret != TC_ACT_OK) {
        ld_bpf_log("route6_is_current_wan_packet: %pI6", context.daddr.bytes);
        return ret;
    }

    ret = tc_route6_lan_redirect_check_in_wan(skb, l3, &context, false);
    if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            route6_set_cache_in_wan(&context, l3, skb->ifindex);
        }
    }

    return ret == TC_ACT_OK ? TC_ACT_OK : ret;
#undef BPF_LOG_TOPIC
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(__u32));
    __array(values, int());
} ls_wan_in_tails SEC(".maps") = {
    .values =
        {
            [TC_INGRESS_V4_SLOT] = (void *)&tc_wan_ingress_route_v4,
            [TC_INGRESS_V6_SLOT] = (void *)&tc_wan_ingress_route_v6,
        },
};

SEC("tc/ingress")
int tc_wan_ingress_exit_redirect(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_wan_ingress_exit_redirect <<<"

    bool is_ipv4;
    int ret;
    u8 l3 = get_wan_ingress_l3_offset(skb);

    if (likely(l3 > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) {
            return ret;
        }
    }

    ret = current_pkg_type(skb, l3, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) {
        return TC_ACT_OK;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_wan_in_tails, TC_INGRESS_V4_SLOT);
        ld_bpf_log("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_wan_in_tails, TC_INGRESS_V6_SLOT);
        ld_bpf_log("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}
