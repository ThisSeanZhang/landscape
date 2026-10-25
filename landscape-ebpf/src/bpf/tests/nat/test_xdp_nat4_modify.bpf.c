#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "nat_v4/xdp_modify_head.h"
#include "nat_v4/xdp_nat4.h"
#include "reader/xdp_read_head4.h"

char LICENSE[] SEC("license") = "GPL";

#define L3_OFFSET sizeof(struct ethhdr)

static __always_inline int run_modify_icmp_error(struct xdp_md *ctx, int from_wan, __be32 new_addr,
                                                 __be16 new_port) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (napt_xdp_modify_icmp_error(data, data_end, new_addr, new_port, from_wan, L3_OFFSET))
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int run_modify(struct xdp_md *ctx, __be32 new_addr, __be16 new_port,
                                      u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (napt_xdp_modify(data, data_end, new_addr, new_port, direction, L3_OFFSET)) return XDP_DROP;
    return XDP_PASS;
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_egress(struct xdp_md *ctx) {
    return run_modify_icmp_error(ctx, 0, bpf_htonl(0xCB007101), bpf_htons(0x5678));
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_ingress(struct xdp_md *ctx) {
    return run_modify_icmp_error(ctx, 1, bpf_htonl(0xC0A80164), bpf_htons(0x1234));
}

SEC("xdp")
int test_xdp_nat4_modify_udp_egress(struct xdp_md *ctx) {
    return run_modify(ctx, bpf_htonl(0xCB007101), bpf_htons(0x5678), LAND_NAT_FRAG_FROM_LAN);
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_udp_egress(struct xdp_md *ctx) {
    return run_modify_icmp_error(ctx, 0, bpf_htonl(0xCB007101), bpf_htons(0x5678));
}

SEC("xdp")
int test_xdp_nat4_read_icmp_error_tcp_quote(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    if (xdp_read_ipv4_nat4(data, data_end, &cb, &src_addr, &dst_addr, L3_OFFSET,
                           LAND_NAT_FRAG_FROM_WAN) != XDP_NAT4_READ_OK)
        return XDP_DROP;

    if (cb.icmp_inner_l4_protocol != IPPROTO_TCP) return XDP_DROP;
    if (src_addr != bpf_htonl(0xC0A80164)) return XDP_DROP;
    if (dst_addr != bpf_htonl(0xC6336414)) return XDP_DROP;
    if (cb.sport != bpf_htons(0x1234)) return XDP_DROP;
    if (cb.dport != bpf_htons(443)) return XDP_DROP;
    return XDP_PASS;
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_tcp_egress(struct xdp_md *ctx) {
    return run_modify_icmp_error(ctx, 0, bpf_htonl(0xCB007101), bpf_htons(0x5678));
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_tcp_ingress(struct xdp_md *ctx) {
    return run_modify_icmp_error(ctx, 1, bpf_htonl(0xC0A80164), bpf_htons(0x1234));
}
