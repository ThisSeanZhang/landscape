#ifndef __LD_ROUTE4_CONTEXT_H__
#define __LD_ROUTE4_CONTEXT_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../pkg_scanner.h"
#include "route_common.h"

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
                                                         const struct packet_offset_info *offset,
                                                         struct route4_context *context) {
#define BPF_LOG_TOPIC "route4_read_context_from_scan"
    if (offset->l3_protocol != LANDSCAPE_IPV4_TYPE) return TC_ACT_UNSPEC;

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, offset->l3_offset_when_scan, sizeof(*iph))) {
        return TC_ACT_SHOT;
    }

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    context->l4_protocol = 0;
    context->tos = iph->tos;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_ROUTE4_CONTEXT_H__ */
