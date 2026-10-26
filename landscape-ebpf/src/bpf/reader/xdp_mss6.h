// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_MSS6_H
#define LAND_XDP_MSS6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv6.h"
#include "base/l4.h"
#include "frag/frag.h"
#include "reader/xdp_ip6_walk.h"

/*
 * XDP MSS-only IPv6 view. Fragment headers (including atomic ones) are
 * ignored, matching the previous full reader's frag_code check.
 */
struct xdp_mss6_view {
    __u32 l4_off;
    __u32 packet_end;
    __u8 frag;
    __u8 next;
    __u8 doff;
    __u8 flags;
};

static __always_inline int xdp_mss6_read(const void *data, const void *data_end, __u32 l3_offset,
                                         struct xdp_mss6_view *view) {
    if (!view) return 0;

    int hlen = xdp_ip6_hdrlen(data, data_end, l3_offset, &view->next, &view->frag,
                              &view->packet_end, 0, 0, 0, 0);
    if (hlen < 0) return 0;

    view->l4_off = l3_offset + (__u32)hlen;
    if (view->frag != LAND_NAT_FRAG_NONE) return 0;
    if (view->next != IPV6_NH_TCP) return 0;
    if (view->l4_off > view->packet_end || view->l4_off + sizeof(struct tcphdr) > view->packet_end)
        return 0;

    const struct tcphdr *tcp = (const struct tcphdr *)((const char *)data + view->l4_off);
    if ((const void *)(tcp + 1) > data_end) return 0;

    view->doff = tcp->doff;
    view->flags = *((const __u8 *)tcp + 13);
    return (view->doff >= 5 && (view->flags & TCP_FLAG_SYN) != 0);
}

#endif /* LAND_XDP_MSS6_H */
