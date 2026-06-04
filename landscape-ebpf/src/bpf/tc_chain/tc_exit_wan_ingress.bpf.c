#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "route_v4.h"
#include "route_v6.h"
#include "route/route_packet.h"

#include "pipeline/tc_cb.h"
#include "pipeline/tc_wan_exit_maps.h"

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
    struct route_context_v4 context = {0};
    struct packet_offset_info offset_info = {0};
    u8 l3 = get_wan_ingress_l3_offset(skb);

    ret = scan_route_packet(skb, l3, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = read_route_context_v4_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route_should_forward_v4(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = is_current_wan_packet_v4(skb, l3, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = lan_redirect_check_v4(skb, l3, &context, false);
    if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            setting_cache_in_wan_v4(&context, l3, skb->ifindex);
        }
    }

    return ret == TC_ACT_OK ? TC_ACT_OK : ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int tc_wan_ingress_route_v6(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_wan_ingress_route_v6"
    int ret = 0;
    struct route_context_v6 context = {0};
    struct packet_offset_info offset_info = {0};
    u8 l3 = get_wan_ingress_l3_offset(skb);

    ret = scan_route_packet(skb, l3, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = read_route_context_v6_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_OK;
    }

    ret = route_should_forward_v6(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = is_current_wan_packet_v6(skb, l3, &context);
    if (ret != TC_ACT_OK) {
        ld_bpf_log("is_current_wan_packet_v6: %pI6", context.daddr.bytes);
        return ret;
    }

    ret = lan_redirect_check_v6(skb, l3, &context, false);
    if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            setting_cache_in_wan_v6(&context, l3, skb->ifindex);
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
int tc_exit_wan_ingress_redirect(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< tc_exit_wan_ingress_redirect <<<"

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
