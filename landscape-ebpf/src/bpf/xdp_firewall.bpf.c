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
#include "frag/frag.h"
#include "reader/xdp_read_head4.h"
#include "reader/xdp_read_head6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = sizeof(struct ethhdr);

static __always_inline bool fw_frag_single(u8 frag_code) {
    return frag_code == LAND_NAT_FRAG_NONE || frag_code == TC_CB_FRAG_SINGLE_V6H;
}

static __always_inline int fw_check_v4(struct xdp_md *ctx, bool block_src, u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    int ret =
        xdp_read_ipv4_nat4(data, data_end, &cb, &src_addr, &dst_addr, current_l3_offset, direction);
    if (ret == XDP_NAT4_READ_DROP) return XDP_PASS;
    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return XDP_DROP;

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = block_src ? src_addr : dst_addr,
    };
    if (bpf_map_lookup_elem(&firewall_block_ip4_map, &key)) return XDP_DROP;

    return XDP_PASS;
}

static __always_inline int fw_check_v6(struct xdp_md *ctx, bool block_src, u8 direction) {
    struct xdp_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    int ret = xdp_read_ipv6_nat6(ctx, &cb, &src_addr, &dst_addr, current_l3_offset, direction);
    if (ret == XDP_NAT6_READ_DROP) return XDP_PASS;
    if (!cb.icmp_inner_l4_offset && !cb.ports_valid && !fw_frag_single(cb.frag_code))
        return XDP_DROP;

    struct ipv6_lpm_key key = {
        .prefixlen = 128,
    };
    __builtin_memcpy(&key.addr, block_src ? &src_addr : &dst_addr, sizeof(key.addr));
    if (bpf_map_lookup_elem(&firewall_block_ip6_map, &key)) return XDP_DROP;

    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_lan_v4(struct xdp_md *ctx) {
    int verdict = fw_check_v4(ctx, false, LAND_NAT_FRAG_FROM_LAN);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_LAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_lan_v6(struct xdp_md *ctx) {
    int verdict = fw_check_v6(ctx, false, LAND_NAT_FRAG_FROM_LAN);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_LAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_lan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_wan_v4(struct xdp_md *ctx) {
    int verdict = fw_check_v4(ctx, true, LAND_NAT_FRAG_FROM_WAN);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_WAN_CHAIN_NEXT_V4(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_wan] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_wan_v6(struct xdp_md *ctx) {
    int verdict = fw_check_v6(ctx, true, LAND_NAT_FRAG_FROM_WAN);
    if (verdict != XDP_PASS) return verdict;

    XDP_FROM_WAN_CHAIN_NEXT_V6(ctx);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    bpf_printk("[fw_wan] all tailcalls failed");
    return XDP_PASS;
}
