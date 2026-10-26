// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_IP4_WALK_H
#define LAND_XDP_IP4_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv4.h"
#include "frag/frag.h"

/*
 * XDP IPv4 L3 navigation. XDP data is linear, so this only validates
 * Ethernet/IPv4 and reports the fields every caller needs, writing directly
 * through the caller's pointers. Returns the IPv4 header length relative to
 * l3_offset, or -1.
 */
static __always_inline int xdp_ip4_hdrlen(const void *data, const void *data_end, __u32 l3_offset,
                                          __u8 *next, __u8 *frag, __u32 *packet_end,
                                          __be16 *frag_id, __be32 *src_addr, __be32 *dst_addr) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset < sizeof(struct ethhdr)) ||
        l3_offset > 255U - sizeof(struct iphdr))
        return -1;

    if (l3_offset != 0) {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end) return -1;
        if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;
    }

    const struct iphdr *iph = (const struct iphdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > data_end) return -1;
    if (iph->version != IPV4_VERSION) return -1;

    __u32 ihl = (__u32)iph->ihl * 4U;
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN) return -1;

    __u32 ip_total = bpf_ntohs(iph->tot_len);
    if (ip_total < ihl) return -1;

    __u32 pkt_len = (__u32)((const char *)data_end - (const char *)data);
    __u32 end = l3_offset + ip_total;
    if (end > pkt_len) return -1;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (ipv4_has_fragment_offset(frag_off))
        *frag = LAND_FRAG_NON_INITIAL;
    else if (frag_off & IPV4_FLAG_MF)
        *frag = LAND_FRAG_FIRST;
    else
        *frag = LAND_FRAG_NONE;

    *next = iph->protocol;
    *packet_end = end;
    if (frag_id) *frag_id = iph->id;
    if (src_addr) *src_addr = iph->saddr;
    if (dst_addr) *dst_addr = iph->daddr;
    return (int)ihl;
}

#endif /* LAND_XDP_IP4_WALK_H */
