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
    if ((iph->frag_off & bpf_htons(0x3fff)) == 0 && iph->ihl >= 5 &&
        (iph->protocol == 6 || iph->protocol == 17)) {
        __be16 *ports = (void *)iph + (u32)iph->ihl * 4;
        if ((void *)(ports + 2) <= data_end) {
            context->src_port = ports[0];
            context->dst_port = ports[1];
            context->l4_protocol = iph->protocol;
            struct tcphdr *tcp = (void *)ports;
            if (context->l4_protocol == 6 && (void *)(tcp + 1) <= data_end && tcp->syn &&
                !tcp->ack) {
                context->tcp_syn = 1;
                context->tcp_syn_seq = tcp->seq;
            }
        }
    }
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

    COPY_ADDR_FROM(context->saddr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);
    struct ip6_scan_offsets off = {};
    if (ip6_scan_ext_linear(data, data_end, 14, IP6_SCAN_MAX_EXT, &off, NULL, NULL, NULL) == 0 &&
        off.frag_code == LAND_FRAG_NONE && (off.l4_protocol == 6 || off.l4_protocol == 17)) {
        __be16 *ports = data + off.l4_offset;
        if ((void *)(ports + 2) <= data_end) {
            context->src_port = ports[0];
            context->dst_port = ports[1];
            context->l4_protocol = off.l4_protocol;
            struct tcphdr *tcp = (void *)ports;
            if (context->l4_protocol == 6 && (void *)(tcp + 1) <= data_end && tcp->syn &&
                !tcp->ack) {
                context->tcp_syn = 1;
                context->tcp_syn_seq = tcp->seq;
            }
        }
    }
    return 0;
}

#endif /* __LD_XDP_ROUTE_READ_H__ */
