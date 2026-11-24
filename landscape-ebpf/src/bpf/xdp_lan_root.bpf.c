#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "chain/from_lan_root.h"
#include "reader/xdp_l3.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_cb.h"
#include "chain/redirect_able.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_from_lan_exit_maps.h"
#include "neigh/neigh_ip4.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct wan_egress_binding egress_binding = {};

/* Updated in place by this WAN's ARP worker. The first six bytes in memory
 * are the MAC in wire order. Zero means the gateway is unresolved. */
volatile __u64 confirmed_gateway_mac;
/* Updated in place by this WAN's NS worker; same layout as above. */
volatile __u64 confirmed_gateway_mac6;

/* Chain id of the owning WAN link; stamped into the packet metadata
 * alongside the mark/target_ifindex written by xdp_lan_route. */
const volatile u32 current_chain = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} root_next_stage SEC(".maps");

static __always_inline int prepare_forwarded_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    const struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return 0;
    if (unlikely(!egress_binding.has_ipv4)) return 0;

    __be32 dst = iph->daddr;
    __be32 mask = egress_binding.wan_mask4;
    // Delegate a directed broadcast to the kernel. Both /31 endpoints are hosts.
    if (unlikely(bpf_ntohl(mask) < 0xfffffffe && (dst | mask) == 0xffffffff)) return 0;

    if (unlikely((dst & mask) == (egress_binding.wan_ip4 & mask))) {
        // On-link: resolve the neighbour MAC like the TC egress root. XDP has
        // no neighbour-pending exit, so an unresolved peer is dropped.
        struct mac_key_v4 key = {.addr = dst};
        struct mac_value_v4 *entry = bpf_map_lookup_elem(&ip_mac_v4, &key);
        if (!entry || entry->ifindex != egress_binding.ifindex || (entry->mac[0] & 1) ||
            is_zero_mac(entry->mac))
            return XDP_DROP;
        __builtin_memcpy(eth->h_dest, entry->mac, sizeof(eth->h_dest));
    } else {
        __u64 mac = confirmed_gateway_mac;
        if (unlikely(!mac)) return XDP_DROP;
        __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
    }
    // Byte loads keep clang from folding the const volatile source.
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
    return 0;
}

static __always_inline int prepare_forwarded_ipv6(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    const struct ipv6hdr *ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end) return 0;
    if (unlikely(!egress_binding.has_ipv6)) return 0;

    const u8 *dst = ip6->daddr.in6_u.u6_addr8;
    if (unlikely((dst[0] & 0xff) == 0xff)) return 0;

    // PD IPv6 egress always targets the upstream gateway; on-link
    // destinations are intentionally unsupported until IPv4/IPv6 on-link
    // handling is unified.
    __u64 mac = confirmed_gateway_mac6;
    if (unlikely(!mac)) return XDP_DROP;
    __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
    return 0;
}

SEC("xdp")
int xdp_lan_root(struct xdp_md *ctx) {
    if (xdp_stamp_chain_id(ctx, current_chain) != 0) {
        bpf_printk("[lan_root] stamp chain meta failed, chain=%u", current_chain);
        return XDP_DROP;
    }

    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_root] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_root] target_ifindex=0");
        return XDP_PASS;
    }

    switch (xdp_classify_l3(ctx)) {
    case XDP_L3_V6:
        if (prepare_forwarded_ipv6(ctx) == XDP_DROP) return XDP_DROP;
        bpf_tail_call_static(ctx, &root_next_stage, XDP_ROOT_SLOT_V6);
        break;
    case XDP_L3_V4:
        if (prepare_forwarded_ipv4(ctx) == XDP_DROP) return XDP_DROP;
        bpf_tail_call_static(ctx, &root_next_stage, XDP_ROOT_SLOT_V4);
        break;
    default:
        // Non-IP packets take no tail call and fall through to the exit.
        break;
    }
    XDP_FROM_LAN_CHAIN_EXIT(ctx);

    bpf_printk("[lan_root] all tailcalls failed");
    return XDP_PASS;
}
