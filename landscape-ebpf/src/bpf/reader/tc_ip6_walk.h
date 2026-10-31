// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_IP6_WALK_H
#define LAND_TC_IP6_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "frag/frag.h"

/*
 * TC compatibility wrapper around ip6_scan_ext(). The IPv6 reader uses the
 * shared walker directly; MSS and other small helpers can keep using this
 * simplified interface.
 */
static __always_inline int tc_ip6_hdrlen(struct __sk_buff *skb, __u32 l3_offset, __u8 *next,
                                         __u8 *frag, __u32 *packet_end, __be32 *frag_id,
                                         __u8 *frag_next, __u8 *tcp_doff, __u8 *tcp_flags,
                                         struct in6_addr *src_addr, struct in6_addr *dst_addr) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return -1;

    struct ip6_scan_offsets off = {};
    __be32 id = 0;
    __u8 fnext = 0;
    __u32 end = 0;
    if (ip6_scan_ext(skb, l3_offset, IP6_SCAN_MAX_EXT, &off, &id, &fnext, &end) < 0) return -1;
    if (end > skb->len || off.l4_offset > end) return -1;

    *next = off.l4_protocol;
    *frag = off.frag_code;
    *packet_end = end;
    if (frag_id) *frag_id = id;
    if (frag_next) *frag_next = fnext;

    char *data = ip6_skb_data(skb);
    char *data_end = ip6_skb_data_end(skb);
    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        if (bpf_skb_pull_data(skb, l3_offset + IPV6_HDR_LEN) != 0) return -1;
        data = ip6_skb_data(skb);
        data_end = ip6_skb_data_end(skb);
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return -1;
    }

    if (src_addr) *src_addr = iph->saddr;
    if (dst_addr) *dst_addr = iph->daddr;

    if (tcp_doff && tcp_flags && off.frag_code == LAND_FRAG_NONE &&
        off.l4_protocol == IPV6_NH_TCP) {
        __u32 hdr_off = off.l4_offset + 12U;
        if (hdr_off + 2U > end) return -1;

        char *p = data + hdr_off;
        if (p + 2 > data_end) {
            if (bpf_skb_pull_data(skb, hdr_off + 2U) != 0) return -1;
            data = ip6_skb_data(skb);
            data_end = ip6_skb_data_end(skb);
            p = data + hdr_off;
            if (p + 2 > data_end) return -1;
        }

        __u16 word;
        __builtin_memcpy(&word, p, sizeof(word));
        *tcp_doff = (word >> 4) & 0xF;
        *tcp_flags = (word >> 8) & 0xFF;
    }

    return (int)(off.l4_offset - l3_offset);
}

#endif /* LAND_TC_IP6_WALK_H */
