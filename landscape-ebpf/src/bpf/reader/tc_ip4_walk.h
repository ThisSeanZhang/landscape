// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_IP4_WALK_H
#define LAND_TC_IP4_WALK_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "frag/frag.h"

/*
 * IPv4 L3 navigation: validate Ethernet/IPv4 and report the fields every
 * caller needs, writing directly through the caller's pointers. The return
 * value is the IPv4 header length (relative to l3_offset), or -1.
 *
 * `frag_id` is optional; callers that do not use the fragment cache pass
 * NULL and the branch folds away after inlining.
 */
static __always_inline int tc_ip4_hdrlen(struct __sk_buff *skb, __u32 l3_offset, __u8 *next,
                                         __u8 *frag, __u32 *packet_end, __be16 *frag_id,
                                         __u8 *tcp_doff, __u8 *tcp_flags, __be32 *src_addr,
                                         __be32 *dst_addr) {
    if (!next || !frag || !packet_end || (l3_offset != 0 && l3_offset < sizeof(struct ethhdr)) ||
        l3_offset > 255U - sizeof(struct iphdr))
        return -1;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            __u32 need = l3_offset + sizeof(struct iphdr);
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return -1;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return -1;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;
    }

    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct iphdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return -1;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct iphdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return -1;
    }
    if (iph->version != IPV4_VERSION) return -1;

    __u32 ihl = (__u32)iph->ihl * 4U;
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN || l3_offset > 255U - ihl) return -1;

    __u32 ip_total = bpf_ntohs(iph->tot_len);
    if (ip_total < ihl) return -1;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (ipv4_has_fragment_offset(frag_off))
        *frag = LAND_FRAG_NON_INITIAL;
    else if (frag_off & IPV4_FLAG_MF)
        *frag = LAND_FRAG_FIRST;
    else
        *frag = LAND_FRAG_NONE;

    *next = iph->protocol;
    *packet_end = l3_offset + ip_total;
    if (frag_id) *frag_id = iph->id;
    if (src_addr) *src_addr = iph->saddr;
    if (dst_addr) *dst_addr = iph->daddr;

    if (tcp_doff && tcp_flags && *next == IPV4_PROTO_TCP) {
        __u32 hdr_off = l3_offset + ihl + 12;
        if (hdr_off + 2 > *packet_end) return -1;
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
    return (int)ihl;
}

#endif /* LAND_TC_IP4_WALK_H */
