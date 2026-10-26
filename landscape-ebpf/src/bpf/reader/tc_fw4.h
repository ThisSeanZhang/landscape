// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_FW4_H
#define LAND_TC_FW4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"

/*
 * Firewall IPv4 view: the block map only needs the address pair. No
 * fragment, L4 or ICMP parsing is involved.
 */
struct tc_fw4_view {
    __be32 src;
    __be32 dst;
};

static __always_inline int tc_fw4_read(struct __sk_buff *skb, __u32 l3_offset,
                                       struct tc_fw4_view *view) {
    if (!view || (l3_offset != 0 && l3_offset < sizeof(struct ethhdr)) ||
        l3_offset > 255U - sizeof(struct iphdr))
        return 0;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            __u32 need = l3_offset + sizeof(struct iphdr);
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return 0;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IP)) return 0;
    }

    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct iphdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct iphdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return 0;
    }
    if (iph->version != IPV4_VERSION) return 0;

    view->src = iph->saddr;
    view->dst = iph->daddr;
    return 1;
}

#endif /* LAND_TC_FW4_H */
