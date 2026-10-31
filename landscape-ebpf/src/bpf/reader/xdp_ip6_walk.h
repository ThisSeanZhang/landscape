// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_IP6_WALK_H
#define LAND_XDP_IP6_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv6.h"
#include "frag/frag.h"

/*
 * XDP IPv6 L3 navigation. XDP data is linear, so this is a thin wrapper over
 * the shared linear extension-header walker. Returns the IPv6 header length
 * relative to l3_offset, or -1.
 */
#define XDP_IP6_WALK_MAX_EXT IP6_SCAN_MAX_EXT

static __always_inline int xdp_ip6_hdrlen(const void *data, const void *data_end, __u32 l3_offset,
                                          __u8 *next, __u8 *frag, __u32 *packet_end,
                                          __be32 *frag_id, __u8 *frag_next,
                                          struct in6_addr *src_addr, struct in6_addr *dst_addr) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return -1;

    struct ip6_scan_offsets off = {};
    __be32 id = 0;
    __u8 fnext = 0;
    __u32 end = 0;
    if (ip6_scan_ext_linear(data, data_end, l3_offset, IP6_SCAN_MAX_EXT, &off, &id, &fnext, &end) <
        0)
        return -1;

    __u32 pkt_len = (__u32)((const char *)data_end - (const char *)data);
    if (end > pkt_len || off.l4_offset > end) return -1;

    *next = off.l4_protocol;
    *frag = off.frag_code;
    *packet_end = end;
    if (frag_id) *frag_id = id;
    if (frag_next) *frag_next = fnext;

    const struct ipv6hdr *iph = (const struct ipv6hdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > (const void *)data_end) return -1;

    if (src_addr) *src_addr = iph->saddr;
    if (dst_addr) *dst_addr = iph->daddr;

    return (int)(off.l4_offset - l3_offset);
}

#endif /* LAND_XDP_IP6_WALK_H */
