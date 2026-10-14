#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "nat/nat_common.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner6.h"
#include "nat/xdp_nat6.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;

#undef BPF_LOG_TOPIC

static __always_inline int nat_v6_egress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v6_egress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct scan_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    struct inet_pair ip_pair = {};
    if (xdp_read_nat_info6(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    __be16 sport = ip_pair.src_port;
    __be16 dport = ip_pair.dst_port;

    if (xdp_frag6_track(&idx, &ip6h->saddr, &ip6h->daddr, &sport, &dport) != XDP_PASS)
        return XDP_DROP;
    ip_pair.src_port = sport;
    ip_pair.dst_port = dport;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    ret =
        xdp_ipv6_egress_prefix_check_and_replace(data, data_end, wan_if, meta.mark, &idx, &ip_pair);
    if (ret) return XDP_DROP;

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

static __always_inline int nat_v6_ingress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v6_ingress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct scan_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    struct inet_pair ip_pair = {};
    if (xdp_read_nat_info6(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    __be16 sport = ip_pair.src_port;
    __be16 dport = ip_pair.dst_port;

    if (xdp_frag6_track(&idx, &ip6h->saddr, &ip6h->daddr, &sport, &dport) != XDP_PASS)
        return XDP_DROP;
    ip_pair.src_port = sport;
    ip_pair.dst_port = dport;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    bool is_static = false;
    ret = xdp_ipv6_ingress_prefix_check_and_replace(data, data_end, wan_if, meta.mark, &idx,
                                                    &ip_pair, &is_static);
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
#undef BPF_LOG_TOPIC
}

SEC("xdp")
int egress_nat_v6(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "egress_nat_v6"
    int ret = nat_v6_egress(ctx);
    if (ret != XDP_PASS) return ret;
    /* Egress NAT (LAN→WAN translation) runs in the LAN-side chain. */
    XDP_FROM_LAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

SEC("xdp")
int ingress_nat_v6(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "ingress_nat_v6"
    int ret = nat_v6_ingress(ctx);
    if (ret != XDP_PASS) return ret;
    /* Ingress NAT (WAN→LAN translation) runs in the WAN-side chain. */
    XDP_FROM_WAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
#undef BPF_LOG_TOPIC
}
