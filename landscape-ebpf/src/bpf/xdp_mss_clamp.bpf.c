#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;

static __always_inline int mss_clamp_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != ETH_IPV4) return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    u32 ip_bytes = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)((void *)iph + ip_bytes);
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    if (!tcph->syn) return XDP_PASS;

    u8 tcp_bytes = tcph->doff * 4;
    if (tcp_bytes <= 20) return XDP_PASS;
    if ((void *)tcph + tcp_bytes > data_end) return XDP_PASS;

    u8 opts_len = tcp_bytes - 20;
    u16 max_mss = mtu_size - (u16)ip_bytes - 20;

    u8 pos = 0;
#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos + 4 > opts_len) break;

        u8 *opt = (u8 *)tcph + 20 + pos;
        if ((void *)(opt + 4) > data_end) break;

        u8 kind = opt[0];
        if (kind == 0) break;
        if (kind == 1) {
            pos += 1;
            continue;
        }

        u8 olen = opt[1];
        if (olen < 2 || olen > 4) break;

        if (kind == 2 && olen == 4) {
            __be16 old_mss = *(__be16 *)(opt + 2);
            if (bpf_ntohs(old_mss) > max_mss) {
                __be16 new_mss = bpf_htons(max_mss);
                *(__be16 *)(opt + 2) = new_mss;
                __s64 d = bpf_csum_diff(&old_mss, sizeof(old_mss), &new_mss, sizeof(new_mss), 0);
                tcph->check = bpf_csum_diff(0, 0, &tcph->check, sizeof(tcph->check), d);
                bpf_printk("[xdp_mss] clamped MSS %u -> %u", bpf_ntohs(old_mss), max_mss);
            }
            break;
        }
        pos += olen;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_clamp_lan(struct xdp_md *ctx) {
    mss_clamp_packet(ctx);

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_clamp_wan(struct xdp_md *ctx) {
    mss_clamp_packet(ctx);

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_WAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_wan, 0);
    return XDP_PASS;
}
