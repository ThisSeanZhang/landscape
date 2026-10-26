// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_IP6_WALK_H
#define LAND_XDP_IP6_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv6.h"
#include "frag/frag.h"

/*
 * XDP IPv6 L3 navigation. XDP data is linear, so this only walks the
 * extension-header chain and writes directly through the caller's pointers;
 * no L4 fields, no fragment cache. Returns the IPv6 header length relative
 * to l3_offset, or -1.
 */
#define XDP_IP6_WALK_MAX_EXT 8U

static __always_inline int xdp_ip6_hdrlen(const void *data, const void *data_end, __u32 l3_offset,
                                          __u8 *next, __u8 *frag, __u32 *packet_end,
                                          __be32 *frag_id, __u8 *frag_next,
                                          struct in6_addr *src_addr, struct in6_addr *dst_addr) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return -1;

    if (l3_offset != 0) {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end) return -1;
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return -1;
    }

    const struct ipv6hdr *iph = (const struct ipv6hdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > data_end) return -1;
    if (iph->version != IPV6_VERSION) return -1;

    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if (payload_len == 0) return -1;

    __u32 pkt_len = (__u32)((const char *)data_end - (const char *)data);
    __u32 end = l3_offset + IPV6_HDR_LEN + payload_len;
    if (end > pkt_len) return -1;

    *next = iph->nexthdr;
    *frag = LAND_FRAG_NONE;
    *packet_end = end;
    if (frag_id) *frag_id = 0;
    if (frag_next) *frag_next = 0;
    if (src_addr) *src_addr = iph->saddr;
    if (dst_addr) *dst_addr = iph->daddr;

    __u8 cur = iph->nexthdr;
    __be32 id = 0;
    __u8 frag_nh = 0;
    __u32 offset = l3_offset + IPV6_HDR_LEN;
    int seen_fragment = 0;

    for (__u32 i = 0; i < XDP_IP6_WALK_MAX_EXT; i++) {
        if (cur == IPV6_NH_FRAGMENT) {
            if (seen_fragment) return -1;

            if (offset + sizeof(struct frag_hdr) > end) return -1;
            const struct frag_hdr *fh = (const struct frag_hdr *)((const char *)data + offset);
            if ((const void *)(fh + 1) > data_end) return -1;

            seen_fragment = 1;
            id = fh->identification;
            frag_nh = fh->nexthdr;
            __be16 frag_off = fh->frag_off;

            if (ipv6_frag_offset(frag_off) != 0) {
                *frag = LAND_FRAG_NON_INITIAL;
                *next = fh->nexthdr;
                if (frag_id) *frag_id = id;
                if (frag_next) *frag_next = frag_nh;
                return (int)(offset + sizeof(struct frag_hdr) - l3_offset);
            }

            *frag = ipv6_frag_more(frag_off) ? LAND_FRAG_FIRST : LAND_FRAG_SINGLE_V6H;
            if (frag_id) *frag_id = id;
            if (frag_next) *frag_next = frag_nh;
            cur = fh->nexthdr;
            offset += sizeof(struct frag_hdr);
            continue;
        }

        if (cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING || cur == IPV6_NH_DSTOPTS) {
            if (offset + sizeof(struct ipv6_opt_hdr) > end) return -1;
            const struct ipv6_opt_hdr *ext =
                (const struct ipv6_opt_hdr *)((const char *)data + offset);
            if ((const void *)(ext + 1) > data_end) return -1;

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
    return (int)(offset - l3_offset);
}

#endif /* LAND_XDP_IP6_WALK_H */
