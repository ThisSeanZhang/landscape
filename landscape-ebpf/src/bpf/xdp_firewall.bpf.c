#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "firewall/firewall_share.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"
#include "reader/xdp_fw4.h"
#include "reader/xdp_fw6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = sizeof(struct ethhdr);

static __always_inline int fw_check_v4(struct xdp_md *ctx, bool block_src) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_fw4_view view = {};

    if (!xdp_fw4_read(data, data_end, current_l3_offset, &view)) return XDP_PASS;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = block_src ? view.src : view.dst,
    };
    if (bpf_map_lookup_elem(&firewall_block_ip4_map, &key)) return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int fw_check_v6(struct xdp_md *ctx, bool block_src) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_fw6_view view = {};

    if (!xdp_fw6_read(data, data_end, current_l3_offset, &view)) return XDP_PASS;

    struct ipv6_lpm_key key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&key.addr, block_src ? &view.src : &view.dst, sizeof(key.addr));
    if (bpf_map_lookup_elem(&firewall_block_ip6_map, &key)) return XDP_DROP;

    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_lan_v4(struct xdp_md *ctx) {
    int verdict = fw_check_v4(ctx, false);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_LAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_lan_v6(struct xdp_md *ctx) {
    int verdict = fw_check_v6(ctx, false);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_LAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_wan_v4(struct xdp_md *ctx) {
    int verdict = fw_check_v4(ctx, true);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_WAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_wan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_wan_v6(struct xdp_md *ctx) {
    int verdict = fw_check_v6(ctx, true);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_WAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_wan] all tailcalls failed");
    return XDP_PASS;
}
