// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_FRAG_H
#define LAND_NAT_FRAG_H

/*
 * Fragment classification shared by the IPv4 and IPv6 datapaths.
 *
 * The packet either carries no Fragment header (NONE), is the first fragment
 * (offset zero and M set), or is a non-initial fragment (offset nonzero). The
 * direction is a property of the TC path, not of the packet.
 */
enum land_nat_frag_type {
    LAND_NAT_FRAG_NONE = 0,
    LAND_NAT_FRAG_FIRST = 1,
    LAND_NAT_FRAG_NON_INITIAL = 2,
};

#define LAND_NAT_FRAG_FROM_LAN 0U
#define LAND_NAT_FRAG_FROM_WAN 1U

/* Reader-internal frag_code for an IPv6 atomic fragment (offset 0, !MF):
 * there is a Fragment header, so L4 must not be parsed, but NAT treats the
 * packet as unfragmented. */
#define LAND_NAT_FRAG_SINGLE_V6H 4

#endif /* LAND_NAT_FRAG_H */
