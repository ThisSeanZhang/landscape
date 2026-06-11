#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner4.h"
#include "scanner/xdp_scanner6.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "nat/xdp_csum_helpers.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;

static __always_inline int mss_clamp_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    enum xdp_l3_proto proto = xdp_classify_l3(ctx);
    if (proto == XDP_L3_ERR || proto == XDP_L3_NONE) return XDP_PASS;

    u16 l4_offset;
    u8 l4_protocol;
    u8 pkt_type;

    if (proto == XDP_L3_V4) {
        struct xdp_ipv4_idx idx;
        if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_PASS;
        l4_offset = idx.l4_offset;
        l4_protocol = idx.l4_protocol;
        pkt_type = idx.pkt_type;
    } else {
        struct xdp_ipv6_idx idx;
        if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_PASS;
        l4_offset = idx.l4_offset;
        l4_protocol = idx.l4_protocol;
        pkt_type = idx.pkt_type;
    }

    if (l4_protocol != IPPROTO_TCP) return XDP_PASS;
    if (pkt_type != PKT_TCP_SYN_V2) return XDP_PASS;

    struct tcphdr *tcph = data + l4_offset;
    if ((void *)(tcph + 1) > data_end) return XDP_PASS;
    u8 tcp_bytes = tcph->doff * 4;
    if (tcp_bytes <= 20) return XDP_PASS;
    if ((void *)tcph + tcp_bytes > data_end) return XDP_PASS;

    u8 opts_len = tcp_bytes - 20;
    u16 ip_hdr_bytes = l4_offset - sizeof(struct ethhdr);
    u16 max_mss = mtu_size - ip_hdr_bytes - 20;

    u8 pos = 0;
    u8 *opt = (u8 *)tcph + 20;

#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos + 4 > opts_len) break;
        if ((void *)(opt + 4) > data_end) break;

        u8 kind = opt[0];
        if (kind == 0) break;

        if (kind == 1) {
            opt++;
            pos++;
        } else {
            u8 olen = opt[1];
            if (olen < 2 || olen > 4) break;

            if (kind == 2 && olen == 4) {
                __be16 old_mss = *(__be16 *)(opt + 2);
                if (bpf_ntohs(old_mss) > max_mss) {
                    __be16 new_mss = bpf_htons(max_mss);
                    *(__be16 *)(opt + 2) = new_mss;
                    __be32 old_mss32 = (__be32)old_mss;
                    __be32 new_mss32 = (__be32)new_mss;
                    __wsum d = bpf_csum_diff(&old_mss32, 4, &new_mss32, 4, 0);
                    tcph->check = xdp_csum_apply(tcph->check, d);
                    // bpf_printk("[xdp_mss] clamped MSS %u -> %u", bpf_ntohs(old_mss), max_mss);
                }
                break;
            }
            opt += olen;
            pos += olen;
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_clamp_lan(struct xdp_md *ctx) {
    mss_clamp_packet(ctx);

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);
    bpf_printk("[mss_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_clamp_wan(struct xdp_md *ctx) {
    mss_clamp_packet(ctx);

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_WAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_wan, 0);
    bpf_printk("[mss_wan] all tailcalls failed");
    return XDP_PASS;
}
