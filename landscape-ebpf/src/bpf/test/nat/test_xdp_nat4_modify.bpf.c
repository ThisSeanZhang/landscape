#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "nat/xdp_nat4.h"

char LICENSE[] SEC("license") = "GPL";

#define OUTER_ICMP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define INNER_IP_OFFSET (OUTER_ICMP_OFFSET + sizeof(struct icmphdr))
#define INNER_L4_OFFSET (INNER_IP_OFFSET + sizeof(struct iphdr))

static __always_inline int run_modify(struct xdp_md *ctx, bool is_modify_source,
                                      const struct nat4_action *action, u8 inner_l4_protocol) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (xdp_modify_headers_v4(data, data_end, OUTER_ICMP_OFFSET, IPPROTO_ICMP, is_modify_source,
                              action, true, INNER_IP_OFFSET, INNER_L4_OFFSET, inner_l4_protocol))
        return XDP_DROP;
    return XDP_PASS;
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_egress(struct xdp_md *ctx) {
    struct nat4_action action = {
        .from_addr.addr = bpf_htonl(0xC0A80164),
        .from_port = bpf_htons(0x1234),
        .to_addr.addr = bpf_htonl(0xCB007101),
        .to_port = bpf_htons(0x5678),
    };
    return run_modify(ctx, true, &action, IPPROTO_ICMP);
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_ingress(struct xdp_md *ctx) {
    struct nat4_action action = {
        .from_addr.addr = bpf_htonl(0xCB007101),
        .from_port = bpf_htons(0x5678),
        .to_addr.addr = bpf_htonl(0xC0A80164),
        .to_port = bpf_htons(0x1234),
    };
    return run_modify(ctx, false, &action, IPPROTO_ICMP);
}

SEC("xdp")
int test_xdp_nat4_read_icmp_error_tcp_quote(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct scan_ipv4_idx idx = {
        .fragment_type = FRAG_SINGLE,
        .l4_protocol = IPPROTO_ICMP,
        .l4_offset = OUTER_ICMP_OFFSET,
        .icmp_error_l3_offset = INNER_IP_OFFSET,
        .icmp_error_inner_l4_offset = INNER_L4_OFFSET,
        .icmp_error_l4_protocol = IPPROTO_TCP,
    };
    struct inet4_pair pair = {};
    if (xdp_read_nat_info4(data, data_end, &idx, &pair)) return XDP_DROP;

    if (idx.icmp_error_l4_protocol != IPPROTO_TCP) return XDP_DROP;
    if (pair.src_addr.addr != bpf_htonl(0xC0A80164)) return XDP_DROP;
    if (pair.dst_addr.addr != bpf_htonl(0xC6336414)) return XDP_DROP;
    if (pair.src_port != bpf_htons(0x1234)) return XDP_DROP;
    if (pair.dst_port != bpf_htons(443)) return XDP_DROP;
    return XDP_PASS;
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_tcp_egress(struct xdp_md *ctx) {
    struct nat4_action action = {
        .from_addr.addr = bpf_htonl(0xC0A80164),
        .from_port = bpf_htons(0x1234),
        .to_addr.addr = bpf_htonl(0xCB007101),
        .to_port = bpf_htons(0x5678),
    };
    return run_modify(ctx, true, &action, IPPROTO_TCP);
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_tcp_ingress(struct xdp_md *ctx) {
    struct nat4_action action = {
        .from_addr.addr = bpf_htonl(0xCB007101),
        .from_port = bpf_htons(0x5678),
        .to_addr.addr = bpf_htonl(0xC0A80164),
        .to_port = bpf_htons(0x1234),
    };
    return run_modify(ctx, false, &action, IPPROTO_TCP);
}
