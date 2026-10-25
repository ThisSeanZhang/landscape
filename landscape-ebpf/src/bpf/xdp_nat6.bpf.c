#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "base/mark.h"
#include "nat/nat_common.h"
#include "nat/xdp_nat6.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"
#include "reader/xdp_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;
const volatile u32 current_l3_offset = sizeof(struct ethhdr);

static __always_inline int nat_v6_egress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    int read_ret = xdp_read_ipv6_nat6(ctx, &cb, &src_addr, &dst_addr, current_l3_offset,
                                      LAND_NAT_FRAG_FROM_LAN);
    if (read_ret < 0) return XDP_DROP;
    if (read_ret == 0) return XDP_PASS;

    if (unlikely(should_nat_skip_protocol(xdp_nat6_outer_protocol(&cb)))) return XDP_PASS;
    if (unlikely(!cb.ports_valid)) return XDP_DROP;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    int ret = xdp_ipv6_egress_prefix_check_and_replace(
        ctx, data, data_end, current_l3_offset, wan_if, meta.mark, &cb, &src_addr, &dst_addr);
    if (ret) return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int nat_v6_ingress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    int read_ret = xdp_read_ipv6_nat6(ctx, &cb, &src_addr, &dst_addr, current_l3_offset,
                                      LAND_NAT_FRAG_FROM_WAN);
    if (read_ret < 0) return XDP_DROP;
    if (read_ret == 0) return XDP_PASS;

    if (unlikely(should_nat_skip_protocol(xdp_nat6_outer_protocol(&cb)))) return XDP_PASS;
    if (unlikely(!cb.ports_valid)) return XDP_DROP;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    bool is_static = false;
    int ret =
        xdp_ipv6_ingress_prefix_check_and_replace(ctx, data, data_end, current_l3_offset, wan_if,
                                                  meta.mark, &cb, &src_addr, &dst_addr, &is_static);
    if (ret == -1) return XDP_DROP;
    if (ret == 1) {
        meta.mark = replace_cache_mask(meta.mark, INGRESS_STATIC_MARK);
        void *dm = (void *)(long)ctx->data_meta;
        if (dm + sizeof(meta) <= data)
            __builtin_memcpy(dm, &meta, sizeof(meta));
        else
            xdp_set_meta(ctx, &meta);
    }
    if (ret == 2) return XDP_PASS;

    return XDP_PASS;
}

SEC("xdp")
int egress_nat_v6(struct xdp_md *ctx) {
    int ret = nat_v6_egress(ctx);
    if (ret != XDP_PASS) return ret;
    /* Egress NAT (LAN→WAN translation) runs in the LAN-side chain. */
    XDP_FROM_LAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
}

SEC("xdp")
int ingress_nat_v6(struct xdp_md *ctx) {
    int ret = nat_v6_ingress(ctx);
    if (ret != XDP_PASS) return ret;
    /* Ingress NAT (WAN→LAN translation) runs in the WAN-side chain. */
    XDP_FROM_WAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
}
