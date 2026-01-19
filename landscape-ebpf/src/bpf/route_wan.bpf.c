#include "vmlinux_wrapper.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "route_v4.h"
#include "route_v6.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u8 LOG_LEVEL = BPF_LOG_LEVEL_DEBUG;


const volatile u32 current_l3_offset = 14;

#undef BPF_LOG_LEVEL
#undef BPF_LOG_TOPIC
#define BPF_LOG_LEVEL LOG_LEVEL


#define IPV4_WAN_INGRESS_PROG_INDEX 0
#define IPV6_WAN_INGRESS_PROG_INDEX 1

#define IPV4_WAN_EGRESS_PROG_INDEX 0
#define IPV6_WAN_EGRESS_PROG_INDEX 1


SEC("tc/ingress")
int rt4_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt4_wan_ingress"
    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v4 context = {0};

    struct iphdr *iph;

    if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(struct iphdr))) {
        bpf_log_info("ipv4 bpf_skb_load_bytes error");
        return TC_ACT_UNSPEC;
    }

    context.l4_protocol = iph->protocol;
    context.daddr = iph->daddr;
    context.saddr = iph->saddr;

    if (should_not_forward(context.daddr)) {
        return TC_ACT_UNSPEC;
    }

    ret = is_current_wan_packet_v4(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = lan_redirect_check_v4(skb, current_l3_offset, &context);
   if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            // bpf_log_info("get wan ingress mark: %u", mark);
            setting_cache_in_wan_v4(&context, current_l3_offset, skb->ifindex);
        }
    }
   
    return ret == TC_ACT_OK ? TC_ACT_UNSPEC : ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int rt4_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt4_wan_egress"

    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v4 context = {0};

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(struct iphdr))) {
        bpf_log_info("ipv4 bpf_skb_load_bytes error");
        u8 *mac;
        if (VALIDATE_READ_DATA(skb, &mac, 6, 6)) {
            bpf_log_info("read mac error");
            return TC_ACT_SHOT;
        }
        PRINT_MAC_ADDR(mac);

        return TC_ACT_SHOT;
    }

    context.l4_protocol = iph->protocol;
    context.daddr = iph->daddr;
    context.saddr = iph->saddr;

    if (should_not_forward(context.daddr)) {
        return TC_ACT_UNSPEC;
    }

      ret = lan_redirect_check_v4(skb, current_l3_offset, &context);
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

    return ret;
#undef BPF_LOG_TOPIC
}


SEC("tc/ingress")
int rt6_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt6_wan_ingress"
    int ret = 0;
    struct route_context_v6 context = {0};

    struct ipv6hdr *ip6h;

    if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(struct ipv6hdr))) {
        bpf_log_info("ipv6 bpf_skb_load_bytes error");
        return TC_ACT_UNSPEC;
    }

    COPY_ADDR_FROM(context.saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context.daddr.all, ip6h->daddr.in6_u.u6_addr32);

    if (is_broadcast_ip6(context.daddr.bytes)) {
        bpf_log_info("is_broadcast_ip6: %pI6", context.daddr.bytes);
        return TC_ACT_UNSPEC;
    }

    ret = is_current_wan_packet_v6(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        bpf_log_info("is_current_wan_packet_v6: %pI6", context.daddr.bytes);
        return ret;
    }

    ret = lan_redirect_check_v6(skb, current_l3_offset, &context);
   if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            // bpf_log_info("get wan ingress mark: %u", mark);
            setting_cache_in_wan_v6(&context, current_l3_offset, skb->ifindex);
        }
    }
   
    // bpf_log_info("lan_redirect_check_v6 ret: %d", ret);
    return ret == TC_ACT_OK ? TC_ACT_UNSPEC : ret;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int rt6_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "rt6_wan_egress"

    int ret = 0;
    u32 flow_mark = skb->mark;
    struct route_context_v6 context = {0};

    struct ipv6hdr *ip6h;

    if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(struct ipv6hdr))) {
        bpf_log_info("ipv6 bpf_skb_load_bytes error");
        return TC_ACT_UNSPEC;
    }

    COPY_ADDR_FROM(context.saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context.daddr.all, ip6h->daddr.in6_u.u6_addr32);

    if (is_broadcast_ip6(context.daddr.bytes)) {
        return TC_ACT_UNSPEC;
    }

      ret = lan_redirect_check_v6(skb, current_l3_offset, &context);
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

    return ret;
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
            [IPV4_WAN_INGRESS_PROG_INDEX] = (void *)&rt4_wan_ingress,
            [IPV6_WAN_INGRESS_PROG_INDEX] = (void *)&rt6_wan_ingress,
        },
};


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(__u32));
    __array(values, int());
} ls_wan_e_tails SEC(".maps") = {
    .values =
        {
            [IPV4_WAN_EGRESS_PROG_INDEX] = (void *)&rt4_wan_egress,
            [IPV6_WAN_EGRESS_PROG_INDEX] = (void *)&rt6_wan_egress,
        },
};

SEC("tc/ingress")
int route_wan_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< route_wan_ingress <<<"

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
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_wan_in_tails, IPV4_WAN_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_wan_in_tails, IPV6_WAN_INGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    }
    
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

SEC("tc/egress")
int route_wan_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< route_wan_egress <<<"

    if (likely(skb->ingress_ifindex != 0)) {
        // 端口转发数据, 相对于是已经决定使用这个出口, 所以直接发送
        return TC_ACT_UNSPEC;
    }

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
        return TC_ACT_UNSPEC;
    }

    if (is_ipv4) {
        bpf_tail_call_static(skb, &ls_wan_e_tails, IPV4_WAN_EGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    } else {
        bpf_tail_call_static(skb, &ls_wan_e_tails, IPV6_WAN_EGRESS_PROG_INDEX);
        bpf_printk("bpf_tail_call_static error");
    }
    
    return TC_ACT_SHOT;
#undef BPF_LOG_TOPIC
}

