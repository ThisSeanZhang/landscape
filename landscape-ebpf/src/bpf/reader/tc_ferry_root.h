// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_TC_FERRY_ROOT_H
#define LAND_NAT_TC_FERRY_ROOT_H

#include <vmlinux.h>

#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "reader/tc_read_head6.h"

/*
 * Root-side ferrying: parse the packet once with the shared readers, then
 * publish the result into skb->cb. The old scanner-based ferry is kept only
 * for stages that still need a fallback scan.
 */

static __always_inline void ferry_root_publish(struct __sk_buff *skb, struct skb_ferry_cb *cb,
                                               bool scan_valid) {
    if (!scan_valid) {
        ferry_publish_invalid(skb);
        return;
    }

    ferry_publish(skb, cb, true);
}

static __always_inline void ferry_root_pack_v4(struct __sk_buff *skb, u32 l3_offset, u8 direction) {
    struct skb_ferry_cb cb = {};
    __be32 src_addr = 0;
    __be32 dst_addr = 0;

    bool ok = tc_read_ipv4(skb, &cb, &src_addr, &dst_addr, l3_offset, direction);
    ferry_root_publish(skb, &cb, ok);
}

static __always_inline void ferry_root_pack_v6(struct __sk_buff *skb, u32 l3_offset, u8 direction) {
    struct skb_ferry_cb cb = {};
    struct in6_addr src_addr = {};
    struct in6_addr dst_addr = {};

    bool ok = tc_read_ipv6(skb, &cb, &src_addr, &dst_addr, l3_offset, direction);
    ferry_root_publish(skb, &cb, ok);
}

#endif /* LAND_NAT_TC_FERRY_ROOT_H */
