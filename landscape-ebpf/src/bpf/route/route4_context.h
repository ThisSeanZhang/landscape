#ifndef __LD_ROUTE4_CONTEXT_H__
#define __LD_ROUTE4_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "chain/xdp_meta.h"
#include "route/route_common.h"

struct route4_context {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    u8 smac[6];
    u8 has_ports;
    u8 l4_parsed;
    u8 _pad[2];
};

static __always_inline int route4_read_context_from_scan(struct __sk_buff *skb,
                                                         const struct route_view *view,
                                                         struct route4_context *context) {
    if (view->l3_protocol != LANDSCAPE_IPV4_TYPE) return TC_ACT_UNSPEC;

    __u32 l3_offset = view->l3_offset;
    if ((u64)l3_offset + sizeof(struct iphdr) > MAX_OFFSET) return TC_ACT_SHOT;

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct iphdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return TC_ACT_SHOT;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        iph = (struct iphdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return TC_ACT_SHOT;
    }

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    context->l4_protocol = 0;
    context->tos = iph->tos;
    return TC_ACT_OK;
}

static __always_inline void route4_ensure_l4_ports_tc(struct __sk_buff *skb, u32 l3_offset,
                                                      struct route4_context *context) {
    if (context->l4_parsed) return;
    context->l4_parsed = 1;
    context->has_ports = 0;

    if (l3_offset > 64U) return;

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        u32 need = l3_offset + sizeof(struct iphdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        iph = (struct iphdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return;
    }

    u8 proto = iph->protocol;
    context->l4_protocol = proto;
    u32 ihl = ((u32)iph->ihl) * 4U;
    if (ihl < sizeof(struct iphdr) || ihl > 60U) return;
    if ((bpf_ntohs(iph->frag_off) & 0x1FFFU) != 0) return;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return;

    u32 l4_off = l3_offset + ihl;
    barrier_var(l4_off);
    if (l4_off > 128U) return;

    char *p = data + l4_off;
    if (p + 4 > data_end) {
        u32 need = l4_off + 4U;
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        p = data + l4_off;
        if (p + 4 > data_end) return;
    }

    __builtin_memcpy(&context->sport, p, 2);
    __builtin_memcpy(&context->dport, p + 2, 2);
    context->has_ports = 1;
}

static __always_inline void route4_ensure_l4_ports_xdp(struct xdp_md *ctx, u32 l3_offset,
                                                       struct route4_context *rctx) {
    if (rctx->l4_parsed) return;
    rctx->l4_parsed = 1;
    rctx->has_ports = 0;

    if (l3_offset > 64U) return;

    char *data = (char *)ctx_data(ctx);
    char *data_end = (char *)ctx_data_end(ctx);
    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) return;

    u8 proto = iph->protocol;
    rctx->l4_protocol = proto;
    u32 ihl = ((u32)iph->ihl) * 4U;
    if (ihl < sizeof(struct iphdr) || ihl > 60U) return;
    if ((bpf_ntohs(iph->frag_off) & 0x1FFFU) != 0) return;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return;

    u32 l4_off = l3_offset + ihl;
    barrier_var(l4_off);
    if (l4_off > 128U) return;

    char *p = data + l4_off;
    if (p + 4 > data_end) return;

    __builtin_memcpy(&rctx->sport, p, 2);
    __builtin_memcpy(&rctx->dport, p + 2, 2);
    rctx->has_ports = 1;
}

#endif /* __LD_ROUTE4_CONTEXT_H__ */
