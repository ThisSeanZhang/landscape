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

static __always_inline void prepare_forwarded_ipv4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    const struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return;

    __be32 dst = iph->daddr;
    __be32 mask = egress_binding.wan_mask4;
    if (unlikely((dst & mask) == (egress_binding.wan_ip4 & mask))) return;
    // Delegate a directed broadcast to the kernel. Both /31 endpoints are hosts.
    if (unlikely(bpf_ntohl(mask) < 0xfffffffe && (dst | mask) == 0xffffffff)) return;

    __u64 mac = confirmed_gateway_mac;
    if (unlikely(!mac)) return;
    __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
    // Byte loads keep clang from folding the const volatile source.
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
}

static __always_inline void prepare_forwarded_ipv6(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    const struct ipv6hdr *ip6 = data + sizeof(*eth);
    if ((void *)(ip6 + 1) > data_end) return;

    const u8 *dst = ip6->daddr.in6_u.u6_addr8;
    if (unlikely((dst[0] & 0xff) == 0xff)) return;

    u8 offlink = 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if ((dst[i] & egress_binding.wan_mask6[i]) !=
            (egress_binding.wan_ip6[i] & egress_binding.wan_mask6[i]))
            offlink = 1;
    }
    if (unlikely(!offlink)) return;

    __u64 mac = confirmed_gateway_mac6;
    if (unlikely(!mac)) return;
    __builtin_memcpy(eth->h_dest, &mac, sizeof(eth->h_dest));
#pragma unroll
    for (int i = 0; i < 6; i++) eth->h_source[i] = egress_binding.source_mac[i];
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
        prepare_forwarded_ipv6(ctx);
        bpf_tail_call_static(ctx, &root_next_stage, XDP_ROOT_SLOT_V6);
        break;
    case XDP_L3_V4:
        prepare_forwarded_ipv4(ctx);
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
