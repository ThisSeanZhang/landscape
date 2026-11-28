#ifndef __LD_ROUTE6_CONTEXT_H__
#define __LD_ROUTE6_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "chain/xdp_meta.h"
#include "route/route_common.h"

struct route6_context {
    struct in6_addr saddr;
    struct in6_addr daddr;
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

static __always_inline int route6_read_context_from_scan(struct __sk_buff *skb,
                                                         const struct route_view *view,
                                                         struct route6_context *context) {
    if (view->l3_protocol != LANDSCAPE_IPV6_TYPE) return TC_ACT_UNSPEC;

    __u32 l3_offset = view->l3_offset;
    if ((u64)l3_offset + sizeof(struct ipv6hdr) > MAX_OFFSET) return TC_ACT_SHOT;

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(ip6h + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct ipv6hdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return TC_ACT_SHOT;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(ip6h + 1) > data_end) return TC_ACT_SHOT;
    }

    COPY_ADDR_FROM(context->saddr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);
    context->l4_protocol = 0;
    context->tos = 0;
    return TC_ACT_OK;
}

static __always_inline void route6_ensure_l4_ports_tc(struct __sk_buff *skb, u32 l3_offset,
                                                      struct route6_context *context) {
    if (context->l4_parsed) return;
    context->l4_parsed = 1;
    context->has_ports = 0;

    if (l3_offset > 64U) return;

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(ip6h + 1) > data_end) {
        u32 need = l3_offset + sizeof(struct ipv6hdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(ip6h + 1) > data_end) return;
    }

    u8 nexthdr = ip6h->nexthdr;
    u32 cur_off = l3_offset + sizeof(struct ipv6hdr);

    if (unlikely(nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)) {
#pragma unroll
        for (int i = 0; i < 2; i++) {
            if (nexthdr == 44) {
                barrier_var(cur_off);
                if (cur_off > 512U) return;
                char *fh = data + cur_off;
                if (fh + 8 > data_end) {
                    u32 need = cur_off + 8U;
                    if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
                    data = skb_data(skb);
                    data_end = skb_data_end(skb);
                    fh = data + cur_off;
                    if (fh + 8 > data_end) return;
                }
                u8 next = *(u8 *)fh;
                __be16 frag_off;
                __builtin_memcpy(&frag_off, fh + 2, 2);
                if ((frag_off & bpf_htons(0xFFF8U)) != 0) {
                    context->l4_protocol = next;
                    return;
                }
                nexthdr = next;
                cur_off += 8U;
            } else if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
                barrier_var(cur_off);
                if (cur_off > 512U) return;
                char *eh = data + cur_off;
                if (eh + 8 > data_end) {
                    u32 need = cur_off + 8U;
                    if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
                    data = skb_data(skb);
                    data_end = skb_data_end(skb);
                    eh = data + cur_off;
                    if (eh + 8 > data_end) return;
                }
                u8 next = *(u8 *)eh;
                u32 ext_len = ((u32)(*(u8 *)(eh + 1)) + 1U) * 8U;
                if (ext_len > 256U) return;
                nexthdr = next;
                cur_off += ext_len;
            } else {
                break;
            }
        }
    }

    context->l4_protocol = nexthdr;
    if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP) return;

    barrier_var(cur_off);
    if (cur_off > 1024U) return;

    char *p = data + cur_off;
    if (p + 4 > data_end) {
        u32 need = cur_off + 4U;
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return;
        data = skb_data(skb);
        data_end = skb_data_end(skb);
        p = data + cur_off;
        if (p + 4 > data_end) return;
    }

    __builtin_memcpy(&context->sport, p, 2);
    __builtin_memcpy(&context->dport, p + 2, 2);
    context->has_ports = 1;
}

static __always_inline void route6_ensure_l4_ports_xdp(struct xdp_md *ctx, u32 l3_offset,
                                                       struct route6_context *rctx) {
    if (rctx->l4_parsed) return;
    rctx->l4_parsed = 1;
    rctx->has_ports = 0;

    if (l3_offset > 64U) return;

    char *data = (char *)ctx_data(ctx);
    char *data_end = (char *)ctx_data_end(ctx);
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(ip6h + 1) > data_end) return;

    u8 nexthdr = ip6h->nexthdr;
    u32 cur_off = l3_offset + sizeof(struct ipv6hdr);

    if (unlikely(nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)) {
#pragma unroll
        for (int i = 0; i < 2; i++) {
            if (nexthdr == 44) {
                barrier_var(cur_off);
                if (cur_off > 512U) return;
                char *fh = data + cur_off;
                if (fh + 8 > data_end) return;
                u8 next = *(u8 *)fh;
                __be16 frag_off;
                __builtin_memcpy(&frag_off, fh + 2, 2);
                if ((frag_off & bpf_htons(0xFFF8U)) != 0) {
                    rctx->l4_protocol = next;
                    return;
                }
                nexthdr = next;
                cur_off += 8U;
            } else if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
                barrier_var(cur_off);
                if (cur_off > 512U) return;
                char *eh = data + cur_off;
                if (eh + 8 > data_end) return;
                u8 next = *(u8 *)eh;
                u32 ext_len = ((u32)(*(u8 *)(eh + 1)) + 1U) * 8U;
                if (ext_len > 256U) return;
                nexthdr = next;
                cur_off += ext_len;
            } else {
                break;
            }
        }
    }

    rctx->l4_protocol = nexthdr;
    if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP) return;

    barrier_var(cur_off);
    if (cur_off > 1024U) return;

    char *p = data + cur_off;
    if (p + 4 > data_end) return;

    __builtin_memcpy(&rctx->sport, p, 2);
    __builtin_memcpy(&rctx->dport, p + 2, 2);
    rctx->has_ports = 1;
}

#endif /* __LD_ROUTE6_CONTEXT_H__ */
