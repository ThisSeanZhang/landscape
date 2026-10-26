// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_MSS4_H
#define LAND_XDP_MSS4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/ipv4.h"
#include "base/l4.h"
#include "frag/frag.h"

/*
 * XDP MSS-only IPv4 view: no addresses, ports, ICMP metadata or fragment
 * cache. XDP data is linear, so headers are read directly.
 */
struct xdp_mss4_view {
    __u32 l4_off;
    __u32 packet_end;
    __u8 frag;
    __u8 next;
    __u8 doff;
    __u8 flags;
};

static __always_inline int xdp_mss4_read(const void *data, const void *data_end, __u32 l3_offset,
                                         struct xdp_mss4_view *view) {
    if (!view || (l3_offset != 0 && l3_offset < sizeof(struct ethhdr)) ||
        l3_offset > 255U - sizeof(struct iphdr))
        return 0;

    if (l3_offset != 0) {
        const struct ethhdr *eth = data;
        if ((const void *)(eth + 1) > data_end) return 0;
        if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;
    }

    const struct iphdr *iph = (const struct iphdr *)((const char *)data + l3_offset);
    if ((const void *)(iph + 1) > data_end) return 0;
    if (iph->version != IPV4_VERSION) return 0;

    __u32 ihl = (__u32)iph->ihl * 4U;
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN || l3_offset > 255U - ihl) return 0;

    __u32 ip_total = bpf_ntohs(iph->tot_len);
    if (ip_total < ihl) return 0;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (ipv4_has_fragment_offset(frag_off))
        view->frag = LAND_FRAG_NON_INITIAL;
    else if (frag_off & IPV4_FLAG_MF)
        view->frag = LAND_FRAG_FIRST;
    else
        view->frag = LAND_FRAG_NONE;

    if (view->frag > LAND_FRAG_FIRST) return 0;
    if (iph->protocol != IPV4_PROTO_TCP) return 0;

    __u32 pkt_len = (__u32)((const char *)data_end - (const char *)data);
    __u32 end = l3_offset + ip_total;
    if (end > pkt_len) return 0;

    __u32 l4_off = l3_offset + ihl;
    if (l4_off > end || l4_off + sizeof(struct tcphdr) > end) return 0;

    const struct tcphdr *tcp = (const struct tcphdr *)((const char *)data + l4_off);
    if ((const void *)(tcp + 1) > data_end) return 0;

    view->l4_off = l4_off;
    view->packet_end = end;
    view->next = IPV4_PROTO_TCP;
    view->doff = tcp->doff;
    view->flags = *((const __u8 *)tcp + 13);
    return (view->doff >= 5 && (view->flags & TCP_FLAG_SYN) != 0);
}

#endif /* LAND_XDP_MSS4_H */
