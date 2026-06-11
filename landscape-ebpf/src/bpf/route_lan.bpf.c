#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "lan_tc_pipeline.h"
#include "landscape.h"
#include "route_v4.h"
#include "route_v6.h"
#include "route/route_packet.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_TOPIC

#define IPV4_LAN_INGRESS_PROG_INDEX 0
#define IPV6_LAN_INGRESS_PROG_INDEX 1

#define IPV4_LAN_EGRESS_PROG_INDEX 0
#define IPV6_LAN_EGRESS_PROG_INDEX 1

SEC("tc/ingress")
int rt4_lan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt4_lan_ingress"
    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v4 context = {0};
    struct packet_offset_info offset_info = {0};

    ret = scan_route_packet(skb, current_l3_offset, &offset_info);
    if (ret == LD_SCAN_ERR) {
        return TC_ACT_SHOT;
    }
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = read_route_context_v4_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = route_should_forward_v4(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = search_route_in_lan_v4(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);
        return ret;
    }

    ret = lan_redirect_check_v4(skb, current_l3_offset, &context, true);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict_v4(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);

    ret = pick_wan_and_send_by_flow_id_v4(skb, current_l3_offset, &context, flow_mark);

    if (ret == TC_ACT_REDIRECT) {
        setting_cache_in_lan_v4(&context, flow_mark);
    }
    return lan_tc_pipeline_continue_ingress(skb, LAN_INGRESS_STAGE_ROUTE, ret);
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int rt6_lan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt6_lan_ingress"
    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v6 context = {0};
    struct packet_offset_info offset_info = {0};

    ret = scan_route_packet(skb, current_l3_offset, &offset_info);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = read_route_context_v6_from_scan(skb, &offset_info, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = route_should_forward_v6(&context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = search_route_in_lan_v6(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);
        return ret;
    }

    ret = lan_redirect_check_v6(skb, current_l3_offset, &context, true);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict_v6(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);

    ret = pick_wan_and_send_by_flow_id_v6(skb, current_l3_offset, &context, flow_mark);

    if (ret == TC_ACT_REDIRECT) {
        setting_cache_in_lan_v6(&context, flow_mark);
    }
    return lan_tc_pipeline_continue_ingress(skb, LAN_INGRESS_STAGE_ROUTE, ret);
#undef BPF_LOG_TOPIC
}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(__u32));
    __array(values, int());
} ls_lan_tails SEC(".maps") = {
    .values =
        {
            [IPV4_LAN_INGRESS_PROG_INDEX] = (void *)&rt4_lan_ingress,
            [IPV6_LAN_INGRESS_PROG_INDEX] = (void *)&rt6_lan_ingress,
        },
};

SEC("tc/ingress")
int route_lan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< route_lan_ingress <<<"

    bool is_ipv4;
    int ret;

    if (likely(current_l3_offset > 0)) {
        ret = is_broadcast_mac(skb);
        if (unlikely(ret != TC_ACT_OK)) {
            return ret;
        }
    }

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (unlikely(ret != TC_ACT_OK)) {
        return lan_tc_pipeline_continue_ingress(skb, LAN_INGRESS_STAGE_ROUTE, TC_ACT_UNSPEC);
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_lan_tails, IPV4_LAN_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_lan_tails, IPV6_LAN_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    }

    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int route_lan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< route_lan_egress <<<"

    return lan_tc_pipeline_continue_egress(skb, LAN_EGRESS_STAGE_ROUTE, TC_ACT_UNSPEC);
#undef BPF_LOG_TOPIC
}
