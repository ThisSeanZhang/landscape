// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_FW6_H
#define LAND_TC_FW6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"

/*
 * Firewall IPv6 view: only the base-header address pair is needed, so this
 * deliberately stops before the extension-header walk.
 */
struct tc_fw6_view {
    struct in6_addr src;
    struct in6_addr dst;
};

static __always_inline int tc_fw6_read(struct __sk_buff *skb, __u32 l3_offset,
                                       struct tc_fw6_view *view) {
    if (!view || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr))) return 0;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            __u32 need = l3_offset + IPV6_HDR_LEN;
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return 0;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return 0;
    }

    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + IPV6_HDR_LEN;
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return 0;
    }
    if (iph->version != IPV6_VERSION) return 0;

    view->src = iph->saddr;
    view->dst = iph->daddr;
    return 1;
}

#endif /* LAND_TC_FW6_H */
