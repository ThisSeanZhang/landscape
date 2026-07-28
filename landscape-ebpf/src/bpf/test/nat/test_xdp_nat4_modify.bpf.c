#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "nat/xdp_nat4.h"

char LICENSE[] SEC("license") = "GPL";

#define OUTER_ICMP_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define INNER_IP_OFFSET (OUTER_ICMP_OFFSET + sizeof(struct icmphdr))
#define INNER_ICMP_OFFSET (INNER_IP_OFFSET + sizeof(struct iphdr))

static __always_inline int run_modify(struct xdp_md *ctx, bool is_modify_source,
                                      const struct nat4_action *action) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (xdp_modify_headers_v4(data, data_end, OUTER_ICMP_OFFSET, IPPROTO_ICMP, is_modify_source,
                              action, true, INNER_IP_OFFSET, INNER_ICMP_OFFSET, IPPROTO_ICMP))
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
    return run_modify(ctx, true, &action);
}

SEC("xdp")
int test_xdp_nat4_modify_icmp_error_ingress(struct xdp_md *ctx) {
    struct nat4_action action = {
        .from_addr.addr = bpf_htonl(0xCB007101),
        .from_port = bpf_htons(0x5678),
        .to_addr.addr = bpf_htonl(0xC0A80164),
        .to_port = bpf_htons(0x1234),
    };
    return run_modify(ctx, false, &action);
}
