#ifndef __LD_SKB_READ_H__
#define __LD_SKB_READ_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../pkg_def.h"
#include "scan_types.h"

static __always_inline int skb_read_ipv4_l3(struct __sk_buff *skb, u32 l3_offset, __be32 *saddr,
                                            __be32 *daddr) {
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, l3_offset, sizeof(*iph))) {
        return TC_ACT_SHOT;
    }
    *saddr = iph->saddr;
    *daddr = iph->daddr;
    return TC_ACT_OK;
}

static __always_inline int skb_read_ipv6_l3(struct __sk_buff *skb, u32 l3_offset,
                                            union u_inet6_addr *saddr, union u_inet6_addr *daddr) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) {
        return TC_ACT_SHOT;
    }
    COPY_ADDR_FROM(saddr->all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(daddr->all, ip6h->daddr.in6_u.u6_addr32);
    return TC_ACT_OK;
}

static __always_inline int skb_read_ipv4_info(struct __sk_buff *skb, u32 l3_offset,
                                              const struct scan_ipv4_idx *idx,
                                              struct inet4_pair *pair) {
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, l3_offset, sizeof(*iph))) {
        return TC_ACT_SHOT;
    }
    pair->src_addr.addr = iph->saddr;
    pair->dst_addr.addr = iph->daddr;

    if (idx->icmp_error_l3_offset > 0) {
        struct iphdr *inner_ip;
        if (VALIDATE_READ_DATA(skb, &inner_ip, idx->icmp_error_l3_offset, sizeof(*inner_ip))) {
            return TC_ACT_SHOT;
        }
        pair->src_addr.addr = inner_ip->daddr;
    }

    if (idx->fragment_type >= FRAG_MIDDLE) {
        return TC_ACT_OK;
    }

    u8 l4_protocol = idx->l4_protocol;
    u16 l4_offset = idx->l4_offset;

    if (idx->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, idx->icmp_error_inner_l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pair->dst_port = tcph->source;
        pair->src_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (idx->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, idx->icmp_error_inner_l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pair->dst_port = udph->source;
        pair->src_port = udph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMP) {
        u32 offset = l4_offset;
        if (idx->icmp_error_inner_l4_offset > 0) {
            offset = idx->icmp_error_inner_l4_offset;
        }
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, offset, sizeof(*icmph))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = pair->dst_port = icmph->un.echo.id;
    }

    return TC_ACT_OK;
}

static __always_inline int skb_read_ipv6_info(struct __sk_buff *skb, u32 l3_offset,
                                              const struct scan_ipv6_idx *idx,
                                              struct inet_pair *pair) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) {
        return TC_ACT_SHOT;
    }
    COPY_ADDR_FROM(pair->src_addr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(pair->dst_addr.all, ip6h->daddr.in6_u.u6_addr32);

    if (idx->icmp_error_l3_offset > 0) {
        struct ipv6hdr *inner_ip6;
        if (VALIDATE_READ_DATA(skb, &inner_ip6, idx->icmp_error_l3_offset, sizeof(*inner_ip6))) {
            return TC_ACT_SHOT;
        }
        COPY_ADDR_FROM(pair->src_addr.all, inner_ip6->daddr.in6_u.u6_addr32);
    }

    if (idx->fragment_type >= FRAG_MIDDLE) {
        return TC_ACT_OK;
    }

    u8 l4_protocol = idx->l4_protocol;
    u16 l4_offset = idx->l4_offset;

    if (idx->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, idx->icmp_error_inner_l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pair->dst_port = tcph->source;
        pair->src_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (idx->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, idx->icmp_error_inner_l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pair->dst_port = udph->source;
        pair->src_port = udph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        u32 offset = l4_offset;
        if (idx->icmp_error_inner_l4_offset > 0) {
            offset = idx->icmp_error_inner_l4_offset;
        }
        struct icmp6hdr *icmp6h;
        if (VALIDATE_READ_DATA(skb, &icmp6h, offset, sizeof(*icmp6h))) {
            return TC_ACT_SHOT;
        }
        pair->src_port = pair->dst_port = icmp6h->icmp6_dataun.u_echo.identifier;
    }

    return TC_ACT_OK;
}

#endif /* __LD_SKB_READ_H__ */
