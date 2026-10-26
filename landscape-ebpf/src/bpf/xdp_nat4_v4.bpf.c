// SPDX-License-Identifier: GPL-2.0-or-later
//
// XDP IPv4 NAT datapath. It uses the same nat_v4 maps and state model as
// tc_nat4_v4, so the TC and XDP programs can share one set of maps.

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/mark.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_stage.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "nat_v4/xdp_modify_head.h"
#include "nat_v4/xdp_nat4.h"
#include "reader/xdp_read_head4.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;
const volatile u32 current_l3_offset = sizeof(struct ethhdr);

static __always_inline void xdp_apply_ingress_static_mark(struct xdp_md *ctx,
                                                          struct xdp_pipe_meta *meta, void *data) {
    meta->mark = replace_cache_mask(meta->mark, INGRESS_STATIC_MARK);
    void *dm = (void *)(long)ctx->data_meta;
    if ((void *)(dm + sizeof(*meta)) <= data)
        __builtin_memcpy(dm, meta, sizeof(*meta));
    else
        xdp_set_meta(ctx, meta);
}

static __always_inline int nat_v4_egress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    int read_ret = xdp_read_ipv4_nat4(data, data_end, &view, &src_addr, &dst_addr,
                                      current_l3_offset, LAND_NAT_FRAG_FROM_LAN);
    if (read_ret < 0) return XDP_DROP;
    if (read_ret == 0) return XDP_PASS;

    if (!xdp_nat4_supported_protocol(view.l4_protocol)) return XDP_PASS;
    if (napt_is_broadcast_ip4(src_addr) || napt_is_broadcast_ip4(dst_addr)) return XDP_PASS;
    if (land_nat_external_addr == 0) return XDP_PASS;

    bool is_icmp_error = view.icmp_inner_l4_offset != 0;
    bool non_initial = view.frag_code == LAND_NAT_FRAG_NON_INITIAL;

    __be32 new_addr = 0;
    __be16 new_port = 0;
    u64 bytes = (u64)(long)data_end - (u64)(long)data;
    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    int rc = xdp_napt_lan_state(&view, src_addr, dst_addr, wan_if, meta.mark, bytes, &new_addr,
                                &new_port);
    if (rc != NAPT_XDP_OK) return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (!non_initial && !is_icmp_error) {
        if (napt_xdp_modify(data, data_end, new_addr, new_port, LAND_NAT_FRAG_FROM_LAN,
                            current_l3_offset))
            return XDP_DROP;
    } else if (non_initial) {
        if (napt_xdp_modify_fragment(data, data_end, new_addr, LAND_NAT_FRAG_FROM_LAN,
                                     current_l3_offset))
            return XDP_DROP;
    } else {
        if (napt_xdp_modify_icmp_error(data, data_end, new_addr, new_port, 0, current_l3_offset))
            return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int nat_v4_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_nat_view view = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;
    int read_ret = xdp_read_ipv4_nat4(data, data_end, &view, &src_addr, &dst_addr,
                                      current_l3_offset, LAND_NAT_FRAG_FROM_WAN);
    if (read_ret < 0) return XDP_DROP;
    if (read_ret == 0) return XDP_PASS;

    if (!xdp_nat4_supported_protocol(view.l4_protocol)) return XDP_PASS;
    if (napt_is_broadcast_ip4(src_addr) || napt_is_broadcast_ip4(dst_addr)) return XDP_PASS;
    if (dst_addr != land_nat_external_addr) return XDP_PASS;

    bool is_icmp_error = view.icmp_inner_l4_offset != 0;
    bool non_initial = view.frag_code == LAND_NAT_FRAG_NON_INITIAL;

    __be32 new_addr = 0;
    __be16 new_port = 0;
    bool is_static = false;
    u64 bytes = (u64)(long)data_end - (u64)(long)data;

    int rc = xdp_napt_wan_state(&view, src_addr, dst_addr, current_ifindex, &meta.mark, bytes,
                                &new_addr, &new_port, &is_static);
    if (rc != NAPT_XDP_OK) return XDP_DROP;

    if (is_static) xdp_apply_ingress_static_mark(ctx, &meta, data);

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (!non_initial && !is_icmp_error) {
        if (napt_xdp_modify(data, data_end, new_addr, new_port, LAND_NAT_FRAG_FROM_WAN,
                            current_l3_offset))
            return XDP_DROP;
    } else if (non_initial) {
        if (napt_xdp_modify_fragment(data, data_end, new_addr, LAND_NAT_FRAG_FROM_WAN,
                                     current_l3_offset))
            return XDP_DROP;
    } else {
        if (napt_xdp_modify_icmp_error(data, data_end, new_addr, new_port, 1, current_l3_offset))
            return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("xdp")
int egress_nat_v4_v4(struct xdp_md *ctx) {
    int ret = nat_v4_egress(ctx);
    if (ret != XDP_PASS) return ret;
    XDP_FROM_LAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
}

SEC("xdp")
int ingress_nat_v4_v4(struct xdp_md *ctx) {
    int ret = nat_v4_ingress(ctx);
    if (ret != XDP_PASS) return ret;
    XDP_FROM_WAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
}
