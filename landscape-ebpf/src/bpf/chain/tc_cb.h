#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

#include <vmlinux.h>

#include "base/proto_def.h"

// Family-indexed chain slots (see chain/tc_stage.h).  Defined here because
// the chain roots do not include tc_stage.h.
#define TC_SLOT_V4 0
#define TC_SLOT_V6 1

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
 *         b24-b31    pkt type
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

// v6-only fragment code: frag header present but offset 0 and !MF
#define TC_CB_FRAG_SINGLE_V6H 4

static __always_inline bool tc_cb_forwarded(const struct __sk_buff *skb) { return skb->cb[0] & 1; }

// pick_wan-style writer: routed decision + target chain id.  Keep the
// accessors whole-word u32: narrow (u16) cb stores make clang derive the
// ctx pointer, which the verifier rejects.
static __always_inline void tc_cb_mark_forwarded(struct __sk_buff *skb, u32 chain_id) {
    u32 cb1 = skb->cb[1];
    skb->cb[0] = 1;
    skb->cb[1] = (cb1 & 0xFFFFu) | (chain_id << 16);
}

static __always_inline u16 tc_cb_chain(const struct __sk_buff *skb) { return skb->cb[1] >> 16; }

static __always_inline u8 tc_cb_l3_offset(const struct __sk_buff *skb) { return skb->cb[1] & 0xFF; }

// ingress chain root stamp (first writer on the path)
static __always_inline void tc_cb_ingress_stamp(struct __sk_buff *skb, u32 l3_offset,
                                                u32 chain_id) {
    skb->cb[1] = (chain_id << 16) | (l3_offset & 0xFF);
}

static __always_inline bool tc_cb_ferry_valid(const struct __sk_buff *skb) {
    return ((skb->cb[0] >> 1) & 0x7FFF) == TC_CB_FERRY_MAGIC && ((skb->cb[0] >> 16) & 1);
}

static __always_inline bool tc_cb_ports_valid(const struct __sk_buff *skb) {
    return (skb->cb[0] >> 17) & 1;
}

static __always_inline u8 tc_cb_frag(const struct __sk_buff *skb) { return (skb->cb[0] >> 18) & 7; }

// frag_track-equivalent of FRAG_SINGLE: no port/cache work for this packet
static __always_inline bool tc_cb_frag_single(const struct __sk_buff *skb) {
    u8 frag = (skb->cb[0] >> 18) & 7;
    return frag == FRAG_SINGLE || frag == TC_CB_FRAG_SINGLE_V6H;
}

// 15-bit unpack: keeps pkt + offset provable for the verifier
// (find_good_pkt_pointers requires umax + hdr size <= MAX_PACKET_OFF).
// Lossless for root-stamped values: the scanner refuses offsets past
// MAX_OFFSET (20480).
static __always_inline u16 tc_cb_l4_offset(const struct __sk_buff *skb) {
    return skb->cb[2] & 0x7FFF;
}

static __always_inline u8 tc_cb_l4_protocol(const struct __sk_buff *skb) {
    return (skb->cb[2] >> 16) & 0xFF;
}

static __always_inline u8 tc_cb_pkt_type(const struct __sk_buff *skb) { return skb->cb[2] >> 24; }

static __always_inline __be16 tc_cb_sport(const struct __sk_buff *skb) {
    return skb->cb[3] & 0xFFFF;
}

static __always_inline __be16 tc_cb_dport(const struct __sk_buff *skb) { return skb->cb[3] >> 16; }

static __always_inline u16 tc_cb_icmp_inner_l4(const struct __sk_buff *skb) {
    return skb->cb[4] & 0x7FFF;
}

static __always_inline u8 tc_cb_icmp_l4_protocol(const struct __sk_buff *skb) {
    return (skb->cb[4] >> 16) & 0xFF;
}

#endif /* __LD_TC_CB_H_ */
