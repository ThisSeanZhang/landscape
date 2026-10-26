#ifndef __LD_ROUTE4_CONTEXT_H__
#define __LD_ROUTE4_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "route/route_common.h"

struct route4_context {
    __be32 saddr;
    __be32 daddr;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    // TODO
    // u16 dst_port;
    u8 smac[6];
};

static __always_inline int route4_read_context_from_scan(struct __sk_buff *skb,
                                                         const struct route_view *view,
                                                         struct route4_context *context) {
    if (view->l3_protocol != LANDSCAPE_IPV4_TYPE) return TC_ACT_UNSPEC;

    __u32 l3_offset = view->l3_offset;
    if ((u64)l3_offset + sizeof(struct iphdr) > MAX_OFFSET) return TC_ACT_SHOT;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct iphdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return TC_ACT_SHOT;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct iphdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return TC_ACT_SHOT;
    }

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    context->l4_protocol = 0;
    context->tos = iph->tos;
    return TC_ACT_OK;
}

#endif /* __LD_ROUTE4_CONTEXT_H__ */
