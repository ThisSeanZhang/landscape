// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_IP6_WALK_H
#define LAND_TC_IP6_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "frag/frag.h"

/*
 * IPv6 L3 navigation: validate Ethernet/IPv6, walk the extension-header chain
 * and report the final protocol plus fragment classification. Everything is
 * written through the caller's pointers; the return value is the IPv6 header
 * length (relative to l3_offset), or -1.
 *
 * `frag_id` / `frag_next` are optional; MSS passes NULL for both and the
 * branches fold away after inlining. On a non-initial fragment the returned
 * length includes the Fragment header and callers must consult `*frag`
 * before treating the result as an L4 offset.
 */
#define IP6_WALK_MAX_EXT 8U
#define IP6_WALK_FRAG_ATOMIC 4U

static __always_inline int tc_ip6_hdrlen(struct __sk_buff *skb, __u32 l3_offset, __u8 *next,
                                         __u8 *frag, __u32 *packet_end, __be32 *frag_id,
                                         __u8 *frag_next, __u8 *tcp_doff, __u8 *tcp_flags) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return -1;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            __u32 need = l3_offset + IPV6_HDR_LEN;
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return -1;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return -1;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return -1;
    }

    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + IPV6_HDR_LEN;
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return -1;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return -1;
    }
    if (iph->version != IPV6_VERSION) return -1;

    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if (payload_len == 0) return -1;

    __u32 end = l3_offset + IPV6_HDR_LEN + payload_len;
    if (end > skb->len) return -1;

    *next = iph->nexthdr;
    *frag = LAND_NAT_FRAG_NONE;
    *packet_end = end;
    if (frag_id) *frag_id = 0;
    if (frag_next) *frag_next = 0;

    __u8 cur = iph->nexthdr;
    __be32 id = 0;
    __u8 frag_nh = 0;
    __u32 offset = l3_offset + IPV6_HDR_LEN;
    int seen_fragment = 0;

    for (__u32 i = 0; i < IP6_WALK_MAX_EXT; i++) {
        if (cur == IPV6_NH_FRAGMENT) {
            if (seen_fragment) return -1;

            __u32 need = offset + sizeof(struct frag_hdr);
            if (need > end) return -1;
            if ((char *)(data + offset) + sizeof(struct frag_hdr) > data_end) {
                if (bpf_skb_pull_data(skb, need) != 0) return -1;
                data = (char *)(long)skb->data;
                data_end = (char *)(long)skb->data_end;
            }

            struct frag_hdr *fh = (struct frag_hdr *)(data + offset);
            if ((char *)(fh + 1) > data_end) return -1;

            seen_fragment = 1;
            id = fh->identification;
            frag_nh = fh->nexthdr;
            __be16 frag_off = fh->frag_off;

            if (ipv6_frag_offset(frag_off) != 0) {
                *frag = LAND_NAT_FRAG_NON_INITIAL;
                *next = fh->nexthdr;
                if (frag_id) *frag_id = id;
                if (frag_next) *frag_next = frag_nh;
                return (int)(offset + sizeof(struct frag_hdr) - l3_offset);
            }

            *frag = ipv6_frag_more(frag_off) ? LAND_NAT_FRAG_FIRST : IP6_WALK_FRAG_ATOMIC;
            if (frag_id) *frag_id = id;
            if (frag_next) *frag_next = frag_nh;
            cur = fh->nexthdr;
            offset += sizeof(struct frag_hdr);
            continue;
        }

        if (cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING || cur == IPV6_NH_DSTOPTS) {
            __u32 need = offset + sizeof(struct ipv6_opt_hdr);
            if (need > end) return -1;
            if ((char *)(data + offset) + sizeof(struct ipv6_opt_hdr) > data_end) {
                if (bpf_skb_pull_data(skb, need) != 0) return -1;
                data = (char *)(long)skb->data;
                data_end = (char *)(long)skb->data_end;
            }

            struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr *)(data + offset);
            if ((char *)(ext + 1) > data_end) return -1;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > end - offset) return -1;

            cur = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        break;
    }

    if (offset > end || offset > 0xFFFFU) return -1;

    *next = cur;
    if (tcp_doff && tcp_flags && *frag == LAND_NAT_FRAG_NONE && cur == IPV6_NH_TCP) {
        __u32 hdr_off = offset + 12;
        if (hdr_off + 2 > end) return -1;
        char *p = data + hdr_off;
        if (p + 2 > data_end) {
            __u32 need = hdr_off + 2;
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return -1;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            p = data + hdr_off;
            if (p + 2 > data_end) return -1;
        }
        /* bpfel target: p[0] is the low byte, p[1] the high byte. */
        __u16 word;
        __builtin_memcpy(&word, p, sizeof(word));
        *tcp_doff = (word >> 4) & 0xF;
        *tcp_flags = (word >> 8) & 0xFF;
    }
    return (int)(offset - l3_offset);
}

#endif /* LAND_TC_IP6_WALK_H */
