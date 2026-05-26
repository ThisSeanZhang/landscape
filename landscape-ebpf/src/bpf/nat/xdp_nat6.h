#ifndef __LD_XDP_NAT6_H__
#define __LD_XDP_NAT6_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "../land_wan_ip.h"
#include "../scanner/xdp_scanner6.h"
#include "../fragment/frag_common.h"
#include "../fragment/xdp_frag6.h"
#include "nat_maps.h"
#include "xdp_csum_helpers.h"

static __always_inline int xdp_read_nat_info6(void *data, void *data_end,
                                              const struct xdp_ipv6_idx *idx,
                                              struct inet_pair *pair) {
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return -1;

    __builtin_memcpy(&pair->src_addr, &ip6h->saddr, sizeof(pair->src_addr));
    __builtin_memcpy(&pair->dst_addr, &ip6h->daddr, sizeof(pair->dst_addr));

    if (idx->icmp_error_l3_offset > 0) {
        struct ipv6hdr *inner_ip6 = data + idx->icmp_error_l3_offset;
        if ((void *)(inner_ip6 + 1) > data_end) return -1;
        __builtin_memcpy(&pair->src_addr, &inner_ip6->daddr, sizeof(pair->src_addr));
    }

    if (idx->fragment_type >= FRAG_MIDDLE) return 0;

    u8 l4_protocol = idx->l4_protocol;
    u16 l4_offset = idx->l4_offset;

    if (idx->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->dst_port = tcph->source;
        pair->src_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (idx->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->dst_port = udph->source;
        pair->src_port = udph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMP || l4_protocol == IPPROTO_ICMPV6) {
        u32 offset = l4_offset;
        if (idx->icmp_error_inner_l4_offset > 0) {
            offset = idx->icmp_error_inner_l4_offset;
        }
        struct icmp6hdr *icmp6h = data + offset;
        if ((void *)(icmp6h + 1) > data_end) return -1;
        pair->src_port = pair->dst_port = icmp6h->icmp6_dataun.u_echo.identifier;
    }

    return 0;
}

static __always_inline int xdp_nat6_egress_prefix_replace(struct xdp_md *ctx, u32 wan_ifindex,
                                                          struct ipv6hdr *ip6h,
                                                          __be64 *old_prefix) {
    struct wan_ip_info_key wan_key = {
        .ifindex = wan_ifindex,
        .l3_protocol = LANDSCAPE_IPV6_TYPE,
    };
    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_info) return -1;

    __builtin_memcpy(old_prefix, &ip6h->saddr, sizeof(*old_prefix));

    __be64 new_prefix;
    __builtin_memcpy(&new_prefix, wan_info->addr.bits, sizeof(new_prefix));

    __be64 replaced = (*old_prefix & wan_info->npt_mask) | (new_prefix & ~wan_info->npt_mask);
    __builtin_memcpy(&ip6h->saddr, &replaced, sizeof(replaced));

    return 0;
}

static __always_inline int xdp_nat6_ingress_prefix_replace(struct xdp_md *ctx, u32 wan_ifindex,
                                                           struct ipv6hdr *ip6h, u16 l4_offset,
                                                           u8 l4_protocol) {
    struct wan_ip_info_key wan_key = {
        .ifindex = wan_ifindex,
        .l3_protocol = LANDSCAPE_IPV6_TYPE,
    };
    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_info) return -1;

    __be64 lan_prefix = 0;
    __builtin_memcpy(&lan_prefix, wan_info->gateway.bits, sizeof(lan_prefix));
    if (lan_prefix == 0) return -1;

    __be64 old_dst_prefix;
    __builtin_memcpy(&old_dst_prefix, &ip6h->daddr, sizeof(old_dst_prefix));

    __be64 replaced = (old_dst_prefix & wan_info->npt_mask) | (lan_prefix & ~wan_info->npt_mask);
    __builtin_memcpy(&ip6h->daddr, &replaced, sizeof(replaced));

    __u32 *old32 = (__u32 *)&old_dst_prefix;
    __u32 *new32 = (__u32 *)&replaced;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        __wsum d = bpf_csum_diff(old32, sizeof(old_dst_prefix), new32, sizeof(replaced), 0);
        tcph->check = xdp_csum_apply(tcph->check, d);
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        if (udph->check != 0) {
            __wsum d = bpf_csum_diff(old32, sizeof(old_dst_prefix), new32, sizeof(replaced), 0);
            udph->check = xdp_csum_apply(udph->check, d);
        }
    }

    return 0;
}

static __always_inline void xdp_nat6_update_l4_checksum(void *data, void *data_end, u16 l4_offset,
                                                        u8 l4_protocol, __be64 old_prefix,
                                                        __be64 new_prefix) {
    __u32 *old32 = (__u32 *)&old_prefix;
    __u32 *new32 = (__u32 *)&new_prefix;

    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return;
        __wsum d = bpf_csum_diff(old32, sizeof(old_prefix), new32, sizeof(new_prefix), 0);
        tcph->check = xdp_csum_apply(tcph->check, d);
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return;
        if (udph->check != 0) {
            __wsum d = bpf_csum_diff(old32, sizeof(old_prefix), new32, sizeof(new_prefix), 0);
            udph->check = xdp_csum_apply(udph->check, d);
        }
    }
}

#endif /* __LD_XDP_NAT6_H__ */
