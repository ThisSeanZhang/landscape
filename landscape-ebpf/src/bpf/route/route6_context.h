#ifndef __LD_ROUTE6_CONTEXT_H__
#define __LD_ROUTE6_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../pkg_scanner.h"
#include "route_common.h"

struct route6_context {
    union u_inet6_addr saddr;
    union u_inet6_addr daddr;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    // TODO
    // u16 dst_port;
    u8 smac[6];
};

static __always_inline int route6_read_context_from_scan(struct __sk_buff *skb,
                                                         const struct packet_offset_info *offset,
                                                         struct route6_context *context) {
#define BPF_LOG_TOPIC "route6_read_context_from_scan"
    if (offset->l3_protocol != LANDSCAPE_IPV6_TYPE) return TC_ACT_UNSPEC;

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, offset->l3_offset_when_scan, sizeof(*ip6h))) {
        return TC_ACT_SHOT;
    }

    COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    context->l4_protocol = 0;
    context->tos = 0;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_ROUTE6_CONTEXT_H__ */
