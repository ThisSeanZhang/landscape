#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/xdp_common.h"
#include "firewall/firewall_share.h"
#include "pipeline/pipeline.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

static __always_inline int firewall_check(struct xdp_md *ctx, bool block_src) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    enum xdp_l3_proto proto = xdp_classify_l3(ctx);
    if (proto != XDP_L3_V4 && proto != XDP_L3_V6) return XDP_PASS;

    if (proto == XDP_L3_V4) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;

        struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .addr = block_src ? iph->saddr : iph->daddr,
        };
        if (bpf_map_lookup_elem(&firewall_block_ip4_map, &key)) return XDP_DROP;
    } else {
        struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
        if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

        struct ipv6_lpm_key key = {
            .prefixlen = 128,
        };
        __builtin_memcpy(&key.addr, block_src ? &ip6h->saddr : &ip6h->daddr, sizeof(key.addr));
        if (bpf_map_lookup_elem(&firewall_block_ip6_map, &key)) return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_lan(struct xdp_md *ctx) {
    int verdict = firewall_check(ctx, false);
    if (verdict != XDP_PASS) return verdict;

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_wan(struct xdp_md *ctx) {
    int verdict = firewall_check(ctx, true);
    if (verdict != XDP_PASS) return verdict;

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_WAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_wan, 0);
    return XDP_PASS;
}
