// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __LD_SKB_FERRY_H__
#define __LD_SKB_FERRY_H__

#include <vmlinux.h>

/*
 * skb->cb layout (5 x u32):
 *
 *   cb[0]  b0        forwarded: set by pick_wan-style writers, read by
 *                    tc_wan_egress_route to enter the target chain
 *         b1-b15     ferry magic (TC_CB_FERRY_MAGIC)
 *         b16        SCAN_VALID
 *         b17        PORTS_VALID
 *         b18-b20    fragment code (FRAG_* or TC_CB_FRAG_SINGLE_V6H)
 *         b21-b31    spare
 *   cb[1]  b0-b7     l3 offset (stamped by the ingress chain root)
 *         b8-b15     spare (0)
 *         b16-b31    chain id (ingress root: own link; forwarded writers:
 *                    target link, low half preserved)
 *   cb[2]  b0-b15    l4 offset
 *         b16-b23    l4 protocol
 *         b24-b31    tcp phase
 *   cb[3]  b0-b15    sport (network order, chain-entry view, pre-NAT)
 *         b16-b31    dport
 *   cb[4]  b0-b15    icmp error inner l4 offset (0 = not an icmp error)
 *         b16-b23    icmp error inner l4 protocol
 *         b24-b31    spare
 *
 * Invariants:
 *  - The chain root that scans the packet rewrites cb[0] preserving only
 *    the forwarded bit; a failed scan stamps the magic with a cleared
 *    bitmap so every stage falls back to its own scan.
 *  - l3/chain writers preserve the other half of cb[1]; the ingress root
 *    is the first writer on its path and owns the whole word.
 *  - cb[2..4] describe the packet as it entered the chain; header-rewriting
 *    stages do not refresh them.
 */
#define TC_CB_FERRY_MAGIC 0x53A2

#ifndef TC_CB_FRAG_SINGLE_V6H
#define TC_CB_FRAG_SINGLE_V6H 4
#endif

/*
 * Typed view of the five skb->cb words.  cb[1..4] are byte-aligned, so they
 * use plain members and _pad arrays; only cb[0] needs bitfields.  The bitfield
 * order matches the little-endian BPF targets (bpfel): the first field
 * occupies the low bits.
 */
struct skb_ferry_cb {
    /* cb[0] */
    __u32 forwarded : 1;
    __u32 magic : 15;
    __u32 scan_valid : 1;
    __u32 ports_valid : 1;
    __u32 frag_code : 3;
    __u32 spare : 11; /* b21-b31, not byte-aligned */

    /* cb[1] */
    __u8 l3_offset;
    __u8 _pad0[1];
    __u16 chain_id;

    /* cb[2] */
    __u16 l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;

    /* cb[3] */
    __be16 sport; /* network order */
    __be16 dport; /* network order */

    /* cb[4] */
    __u16 icmp_inner_l4_offset;
    __u8 icmp_inner_l4_protocol;
    __u8 _pad1[1];
};
_Static_assert(sizeof(struct skb_ferry_cb) == 5 * sizeof(__u32),
               "skb_ferry_cb must overlay the five skb->cb words");

#endif /* __LD_SKB_FERRY_H__ */