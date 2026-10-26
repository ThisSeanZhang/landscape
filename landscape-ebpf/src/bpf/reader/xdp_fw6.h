// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_FW6_H
#define LAND_XDP_FW6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv6.h"

/*
 * XDP firewall IPv6 view: the base header is enough for the block map, so
 * this stops before the extension-header walk.
 */
struct xdp_fw6_view {
    struct in6_addr src;
    struct in6_addr dst;
};

static __always_inline int xdp_fw6_read(const void *data, const void *data_end, __u32 l3_offset,
                                        struct xdp_fw6_view *view) {
    if (!view || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr))) return 0;

    if (l3_offset != 0) {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end) return 0;
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return 0;
    }

    const struct ipv6hdr *iph = (const struct ipv6hdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > data_end) return 0;
    if (iph->version != IPV6_VERSION) return 0;

    view->src = iph->saddr;
    view->dst = iph->daddr;
    return 1;
}

#endif /* LAND_XDP_FW6_H */
