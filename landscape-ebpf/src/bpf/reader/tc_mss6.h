// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_MSS6_H
#define LAND_TC_MSS6_H

#include <vmlinux.h>

#include "base/ipv6.h"
#include "base/l4.h"
#include "frag/frag.h"
#include "reader/tc_ip6_walk.h"

/*
 * MSS-only IPv6 view. Fragment headers (including atomic ones) are ignored,
 * matching the previous full reader's `frag_code != LAND_FRAG_NONE`
 * check.
 */
struct tc_mss6_view {
    __u32 l4_off;
    __u32 packet_end;
    __u8 frag;
    __u8 next;
    __u8 doff;
    __u8 flags;
};

static __always_inline int tc_mss6_read(struct __sk_buff *skb, __u32 l3_offset,
                                        struct tc_mss6_view *view) {
    if (!view) return 0;

    int hlen = tc_ip6_hdrlen(skb, l3_offset, &view->next, &view->frag, &view->packet_end, 0, 0,
                             &view->doff, &view->flags, 0, 0);
    if (hlen < 0) return 0;

    view->l4_off = l3_offset + (__u32)hlen;
    if (view->frag != LAND_FRAG_NONE) return 0;
    if (view->next != IPV6_NH_TCP) return 0;
    if (view->l4_off + sizeof(struct tcphdr) > view->packet_end) return 0;

    return (view->flags & TCP_FLAG_SYN) != 0;
}

#endif /* LAND_TC_MSS6_H */
