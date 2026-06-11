#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "land_nat6_v3.h"
#include "landscape.h"
#include "nat/nat_packet.h"

char LICENSE[] SEC("license") = "GPL";

#undef BPF_LOG_TOPIC

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int handle_ipv6_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< handle_ipv6_egress <<<"

    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = read_nat_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = ipv6_egress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair, skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

SEC("tc/ingress")
int handle_ipv6_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "<<< handle_ipv6_ingress <<<"

    struct packet_offset_info pkg_offset = {0};
    struct inet_pair ip_pair = {0};
    int ret = 0;

    ret = scan_nat_packet(skb, current_l3_offset, &pkg_offset);
    if (ret) {
        return ret;
    }

    ret = is_handle_protocol(pkg_offset.l4_protocol);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    if (pkg_offset.l3_protocol != LANDSCAPE_IPV6_TYPE) {
        return TC_ACT_OK;
    }

    ret = read_nat_packet_info(skb, &pkg_offset, &ip_pair);
    if (ret) {
        return ret;
    }

    ret = ipv6_ingress_prefix_check_and_replace(skb, &pkg_offset, &ip_pair, skb->ifindex);
    if (ret) {
        return ret;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}
