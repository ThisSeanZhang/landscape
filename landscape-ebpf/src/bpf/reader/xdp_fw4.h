// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_FW4_H
#define LAND_XDP_FW4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv4.h"

/*
 * XDP firewall IPv4 view. XDP data is already linear, so this needs no
 * pull path and stops at the base-header address pair.
 */
struct xdp_fw4_view {
    __be32 src;
    __be32 dst;
};

static __always_inline int xdp_fw4_read(const void *data, const void *data_end, __u32 l3_offset,
                                        struct xdp_fw4_view *view) {
    if (!view || (l3_offset != 0 && l3_offset < sizeof(struct ethhdr)) ||
        l3_offset > 255U - sizeof(struct iphdr))
        return 0;

    if (l3_offset != 0) {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end) return 0;
        if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;
    }

    const struct iphdr *iph = (const struct iphdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > data_end) return 0;
    if (iph->version != IPV4_VERSION) return 0;

    view->src = iph->saddr;
    view->dst = iph->daddr;
    return 1;
}

#endif /* LAND_XDP_FW4_H */
