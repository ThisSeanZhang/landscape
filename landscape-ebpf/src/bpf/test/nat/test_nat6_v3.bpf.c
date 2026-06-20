#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "land_nat6_v3.h"
#include "landscape.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"

char LICENSE[] SEC("license") = "GPL";

#undef BPF_LOG_TOPIC

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int handle_ipv6_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< handle_ipv6_egress <<<"

    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    if (scan_ipv6_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) {
        return TC_ACT_SHOT;
    }

    ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret) {
        return ret;
    }

    ret =
        ipv6_egress_prefix_check_and_replace(skb, &idx, &ip_pair, current_l3_offset, skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int handle_ipv6_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< handle_ipv6_ingress <<<"

    struct scan_ipv6_idx idx = {};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    if (scan_ipv6_full(skb, current_l3_offset, &idx) != LD_SCAN_OK) {
        return TC_ACT_SHOT;
    }

    ret = is_handle_protocol(idx.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = skb_read_ipv6_info(skb, current_l3_offset, &idx, &ip_pair);
    if (ret) {
        return ret;
    }

    ret =
        ipv6_ingress_prefix_check_and_replace(skb, &idx, &ip_pair, current_l3_offset, skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
