#ifndef __LD_XDP_ROUTE_READ_H__
#define __LD_XDP_ROUTE_READ_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "route/route4_context.h"
#include "route/route6_context.h"

static __always_inline int xdp_read_ipv4(struct xdp_md *ctx, struct route4_context *context) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != ETH_IPV4) return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    return 0;
}

static __always_inline int xdp_read_ipv6(struct xdp_md *ctx, struct route6_context *context) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != ETH_IPV6) return XDP_PASS;

    ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) return XDP_DROP;

    COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    return 0;
}

#endif /* __LD_XDP_ROUTE_READ_H__ */
