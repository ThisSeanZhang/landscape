/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_XDP_NAT_VIEW_H
#define LAND_XDP_NAT_VIEW_H

#include <vmlinux.h>

/*
 * XDP per-packet parser output. This is stack-local scratch state; it is not
 * stored in data_meta and is not carried across tail calls.
 *
 * The L3 offset is not stored; callers pass their configured l3_offset to
 * the reader explicitly.
 */
struct xdp_nat_view {
    __u16 l4_offset;
    __be16 sport;
    __be16 dport;
    __u16 icmp_inner_l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;
    __u8 icmp_inner_l4_protocol;
    __u8 frag_code;
    __u8 ports_valid;
    __u8 _pad[3];
};

#endif /* LAND_XDP_NAT_VIEW_H */
