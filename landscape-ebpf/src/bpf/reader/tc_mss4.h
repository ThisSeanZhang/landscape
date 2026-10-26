// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_MSS4_H
#define LAND_TC_MSS4_H

#include <vmlinux.h>

#include "base/l4.h"
#include "frag/frag.h"
#include "reader/tc_ip4_walk.h"

/*
 * MSS-only IPv4 view. No address pair, ports, TCP phase, ICMP metadata or
 * fragment cache; just the navigation fields and the TCP SYN bit.
 */
struct tc_mss4_view {
    __u32 l4_off;
    __u32 packet_end;
    __u8 frag;
    __u8 next;
    __u8 doff;
    __u8 flags;
};

static __always_inline int tc_mss4_read(struct __sk_buff *skb, __u32 l3_offset,
                                        struct tc_mss4_view *view) {
    if (!view) return 0;

    int ihl = tc_ip4_hdrlen(skb, l3_offset, &view->next, &view->frag, &view->packet_end, 0,
                            &view->doff, &view->flags, 0, 0);
    if (ihl < 0) return 0;

    view->l4_off = l3_offset + (__u32)ihl;
    if (view->frag > LAND_NAT_FRAG_FIRST) return 0;
    if (view->next != IPV4_PROTO_TCP) return 0;
    if (view->l4_off + sizeof(struct tcphdr) > view->packet_end) return 0;

    return (view->flags & TCP_FLAG_SYN) != 0;
}

#endif /* LAND_TC_MSS4_H */
