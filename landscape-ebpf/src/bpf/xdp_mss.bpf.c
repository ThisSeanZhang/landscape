#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"
#include "frag/frag.h"
#include "nat/xdp_csum_helpers.h"
#include "reader/xdp_read_head4.h"
#include "reader/xdp_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 mtu_size = 1492;

const volatile u32 current_l3_offset = sizeof(struct ethhdr);

static __always_inline void mss_clamp_tcp_opts(void *data, void *data_end, u16 l4_offset,
                                               u16 ip_hdr_bytes) {
    struct tcphdr *tcph = data + l4_offset;
    if ((void *)(tcph + 1) > data_end) return;
    u8 tcp_bytes = tcph->doff * 4;
    if (tcp_bytes <= 20) return;
    if ((void *)tcph + tcp_bytes > data_end) return;

    u8 opts_len = tcp_bytes - 20;
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
                }
                break;
            }
            opt += olen;
            pos += olen;
        }
    }
}

static __always_inline int mss_clamp_v4(struct xdp_md *ctx, u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    int ret =
        xdp_read_ipv4_nat4(data, data_end, &cb, &src_addr, &dst_addr, current_l3_offset, direction);
    if (ret != XDP_NAT4_READ_OK) return XDP_PASS;
    if (cb.icmp_inner_l4_offset) return XDP_PASS;
    if (cb.frag_code > LAND_NAT_FRAG_FIRST) return XDP_PASS;
    if (cb.l4_protocol != IPV4_PROTO_TCP) return XDP_PASS;
    if (cb.tcp_phase != NAPT_TCP_PHASE_SYN) return XDP_PASS;
    if (cb.l4_offset < current_l3_offset) return XDP_PASS;

    u32 ip_hdr_bytes = cb.l4_offset - current_l3_offset;
    if (ip_hdr_bytes + 20U >= mtu_size) return XDP_PASS;

    mss_clamp_tcp_opts(data, data_end, cb.l4_offset, (u16)ip_hdr_bytes);
    return XDP_PASS;
}

static __always_inline int mss_clamp_v6(struct xdp_md *ctx, u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    int ret = xdp_read_ipv6_nat6(ctx, &cb, &src_addr, &dst_addr, current_l3_offset, direction);
    if (ret != XDP_NAT6_READ_OK) return XDP_PASS;
    if (cb.icmp_inner_l4_offset) return XDP_PASS;
    if (cb.frag_code != LAND_NAT_FRAG_NONE) return XDP_PASS;
    if (cb.l4_protocol != IPV6_NH_TCP) return XDP_PASS;
    if (cb.tcp_phase != NAPT_TCP_PHASE_SYN) return XDP_PASS;
    if (cb.l4_offset < current_l3_offset) return XDP_PASS;

    u32 ip_hdr_bytes = cb.l4_offset - current_l3_offset;
    if (ip_hdr_bytes + 20U >= mtu_size) return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    mss_clamp_tcp_opts(data, data_end, cb.l4_offset, (u16)ip_hdr_bytes);
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_lan_v4(struct xdp_md *ctx) {
    mss_clamp_v4(ctx, LAND_NAT_FRAG_FROM_LAN);

    XDP_FROM_LAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[mss_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_lan_v6(struct xdp_md *ctx) {
    mss_clamp_v6(ctx, LAND_NAT_FRAG_FROM_LAN);

    XDP_FROM_LAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[mss_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_wan_v4(struct xdp_md *ctx) {
    mss_clamp_v4(ctx, LAND_NAT_FRAG_FROM_WAN);

    XDP_FROM_WAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[mss_wan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_mss_wan_v6(struct xdp_md *ctx) {
    mss_clamp_v6(ctx, LAND_NAT_FRAG_FROM_WAN);

    XDP_FROM_WAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[mss_wan] all tailcalls failed");
    return XDP_PASS;
}
