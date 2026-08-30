#ifndef __LD_NEIGH_LEARN_H__
#define __LD_NEIGH_LEARN_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "landscape.h"
#include "neigh_ip4.h"
#include "neigh_ip6.h"
#include "route/route_index.h"

static __always_inline void learn_src_ip_mac_v4_xdp(struct xdp_md *ctx,
                                                    const struct route_context_v4 *context) {
    struct mac_key_v4 src_key = {.addr = context->saddr};
    if (bpf_map_lookup_elem(&ip_mac_v4, &src_key) != NULL) return;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return;

    struct mac_value_v4 new_val = {
        .ifindex = ctx->ingress_ifindex,
        .proto = ETH_IPV4,
    };
    __builtin_memcpy(new_val.mac, eth->h_source, 6);
    bpf_map_update_elem(&ip_mac_v4, &src_key, &new_val, BPF_NOEXIST);
}

static __always_inline void learn_src_ip_mac_v6_xdp(struct xdp_md *ctx,
                                                    const struct route_context_v6 *context) {
    struct mac_key_v6 src_key = {};
    COPY_ADDR_FROM(src_key.addr.bytes, context->saddr.bytes);
    if (bpf_map_lookup_elem(&ip_mac_v6, &src_key) != NULL) return;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return;

    struct mac_value_v6 new_val = {
        .ifindex = ctx->ingress_ifindex,
        .proto = ETH_IPV6,
    };
    __builtin_memcpy(new_val.mac, eth->h_source, 6);
    bpf_map_update_elem(&ip_mac_v6, &src_key, &new_val, BPF_NOEXIST);
}

static __always_inline void learn_src_ip_mac_v4_tc(struct __sk_buff *skb,
                                                   const struct route_context_v4 *context,
                                                   u32 current_l3_offset) {
    if (unlikely(current_l3_offset == 0)) return;

    struct mac_key_v4 src_key = {.addr = context->saddr};
    if (bpf_map_lookup_elem(&ip_mac_v4, &src_key) != NULL) return;

    u8 src_mac[6];
    // Ethernet frames start with the destination MAC; the source MAC is at
    // offset 6 (the XDP variants read eth->h_source).
    if (bpf_skb_load_bytes(skb, 6, src_mac, sizeof(src_mac))) return;

    struct mac_value_v4 new_val = {
        .ifindex = skb->ingress_ifindex,
        .proto = ETH_IPV4,
    };
    __builtin_memcpy(new_val.mac, src_mac, 6);
    bpf_map_update_elem(&ip_mac_v4, &src_key, &new_val, BPF_NOEXIST);
}

static __always_inline void learn_src_ip_mac_v6_tc(struct __sk_buff *skb,
                                                   const struct route_context_v6 *context,
                                                   u32 current_l3_offset) {
    if (unlikely(current_l3_offset == 0)) return;

    struct mac_key_v6 src_key = {};
    COPY_ADDR_FROM(src_key.addr.bytes, context->saddr.bytes);
    if (bpf_map_lookup_elem(&ip_mac_v6, &src_key) != NULL) return;

    u8 src_mac[6];
    // Ethernet frames start with the destination MAC; the source MAC is at
    // offset 6 (the XDP variants read eth->h_source).
    if (bpf_skb_load_bytes(skb, 6, src_mac, sizeof(src_mac))) return;

    struct mac_value_v6 new_val = {
        .ifindex = skb->ingress_ifindex,
        .proto = ETH_IPV6,
    };
    __builtin_memcpy(new_val.mac, src_mac, 6);
    bpf_map_update_elem(&ip_mac_v6, &src_key, &new_val, BPF_NOEXIST);
}

#endif /* __LD_NEIGH_LEARN_H__ */
