// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_NAT_VIEW_H
#define LAND_TC_NAT_VIEW_H

#include <vmlinux.h>

/*
 * Stack-local result of the shared TC L3/L4 reader. Consumed by NAT4/NAT6.
 * It is a plain local view; nothing is stored in skb->cb.
 */
struct tc_nat_view {
    __u8 l3_offset;
    __u16 l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;
    __be16 sport;
    __be16 dport;
    __u16 icmp_inner_l4_offset;
    __u8 icmp_inner_l4_protocol;
    __u8 frag_code;
    __u8 ports_valid;
};

#endif /* LAND_TC_NAT_VIEW_H */
