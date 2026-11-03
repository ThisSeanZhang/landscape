#ifndef __LD_ROUTE6_CONTEXT_H__
#define __LD_ROUTE6_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "base/ipv6.h"
#include "route/route_common.h"

struct route6_context {
    struct in6_addr saddr;
    struct in6_addr daddr;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    __be16 src_port;
    __be16 dst_port;
    u8 smac[6];
    u8 tcp_syn;
    __be32 tcp_syn_seq;
};

static __always_inline int route6_read_context_from_scan(struct __sk_buff *skb,
                                                         const struct route_view *view,
                                                         struct route6_context *context) {
    if (view->l3_protocol != LANDSCAPE_IPV6_TYPE) return TC_ACT_UNSPEC;

    __u32 l3_offset = view->l3_offset;
    if ((u64)l3_offset + sizeof(struct ipv6hdr) > MAX_OFFSET) return TC_ACT_SHOT;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(ip6h + 1) > data_end) {
        __u32 need = l3_offset + sizeof(struct ipv6hdr);
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return TC_ACT_SHOT;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        ip6h = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(ip6h + 1) > data_end) return TC_ACT_SHOT;
    }

    COPY_ADDR_FROM(context->saddr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);
    context->tos = 0;
    struct ip6_scan_offsets off = {};
    if (ip6_scan_ext(skb, l3_offset, IP6_SCAN_MAX_EXT, &off, NULL, NULL, NULL) == 0 &&
        off.frag_code == LAND_FRAG_NONE && (off.l4_protocol == 6 || off.l4_protocol == 17)) {
        __be16 ports[2];
        if (bpf_skb_load_bytes(skb, off.l4_offset, ports, sizeof(ports)) == 0) {
            context->src_port = ports[0];
            context->dst_port = ports[1];
            context->l4_protocol = off.l4_protocol;
            if (context->l4_protocol == 6) {
                struct tcphdr tcp;
                if (bpf_skb_load_bytes(skb, off.l4_offset, &tcp, sizeof(tcp)) == 0 && tcp.syn &&
                    !tcp.ack) {
                    context->tcp_syn = 1;
                    context->tcp_syn_seq = tcp.seq;
                }
            }
        }
    }
    return TC_ACT_OK;
}

#endif /* __LD_ROUTE6_CONTEXT_H__ */
