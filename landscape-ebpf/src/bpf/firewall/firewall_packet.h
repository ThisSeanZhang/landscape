#ifndef LD_FIREWALL_PACKET_H
#define LD_FIREWALL_PACKET_H

#include <vmlinux.h>

#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../landscape_log.h"
#include "../pkg_scanner.h"

#define FIREWALL_ICMP_ERR_PACKET_L4_LEN 8

static __always_inline __be16 firewall_get_icmpx_query_id(struct icmphdr *icmph) {
    return icmph->un.echo.id;
}

static __always_inline __be16 firewall_get_icmp6_query_id(struct icmp6hdr *icmp6h) {
    return icmp6h->icmp6_dataun.u_echo.identifier;
}

static __always_inline int firewall_read_l4_info(struct __sk_buff *skb, u8 l4_protocol, u32 offset,
                                                 bool icmp_error_inner, struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "firewall_read_l4_info"
    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        u32 read_len = icmp_error_inner ? FIREWALL_ICMP_ERR_PACKET_L4_LEN : sizeof(*tcph);
        if (VALIDATE_READ_DATA(skb, &tcph, offset, read_len)) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = tcph->source;
        ip_pair->dst_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        u32 read_len = icmp_error_inner ? FIREWALL_ICMP_ERR_PACKET_L4_LEN : sizeof(*udph);
        if (VALIDATE_READ_DATA(skb, &udph, offset, read_len)) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = udph->source;
        ip_pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        u32 read_len = icmp_error_inner ? FIREWALL_ICMP_ERR_PACKET_L4_LEN : sizeof(*icmph);
        if (VALIDATE_READ_DATA(skb, &icmph, offset, read_len)) {
            return TC_ACT_SHOT;
        }
        switch (icmp_msg_type(icmph)) {
        case ICMP_QUERY_MSG:
            ip_pair->src_port = ip_pair->dst_port = firewall_get_icmpx_query_id(icmph);
            break;
        case ICMP_ERROR_MSG:
        case ICMP_ACT_UNSPEC:
            return TC_ACT_UNSPEC;
        default:
            return TC_ACT_SHOT;
        }
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        if (icmp_error_inner) return TC_ACT_UNSPEC;

        struct icmp6hdr *icmp6h;
        if (VALIDATE_READ_DATA(skb, &icmp6h, offset, sizeof(*icmp6h))) {
            return TC_ACT_SHOT;
        }
        switch (icmp6_msg_type(icmp6h)) {
        case ICMP_QUERY_MSG:
            ip_pair->src_port = ip_pair->dst_port = firewall_get_icmp6_query_id(icmp6h);
            break;
        case ICMP_ERROR_MSG:
        case ICMP_ACT_UNSPEC:
            return TC_ACT_UNSPEC;
        default:
            return TC_ACT_SHOT;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int extract_firewall_packet_info(struct __sk_buff *skb,
                                                        struct packet_offset_info *offset_info,
                                                        struct inet_pair *ip_pair,
                                                        u32 current_l3_offset) {
#define BPF_LOG_TOPIC "extract_firewall_packet_info"
    if (offset_info == NULL || ip_pair == NULL) return TC_ACT_SHOT;

    int ret = scan_packet_full(skb, current_l3_offset, offset_info);
    if (ret != LD_SCAN_OK) return ret;

    if (offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset_info->l3_offset_when_scan, sizeof(*iph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_addr.ip = iph->saddr;
        ip_pair->dst_addr.ip = iph->daddr;
    } else if (offset_info->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->l3_offset_when_scan, sizeof(*ip6h))) {
            return TC_ACT_SHOT;
        }
        COPY_ADDR_FROM(ip_pair->src_addr.all, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(ip_pair->dst_addr.all, ip6h->daddr.in6_u.u6_addr32);
    } else {
        return TC_ACT_UNSPEC;
    }

    if (offset_info->fragment_type >= FRAG_MIDDLE) {
        ip_pair->src_port = 0;
        ip_pair->dst_port = 0;
        return TC_ACT_OK;
    }

    if (is_icmp_error_pkt(offset_info)) {
        union u_inet_addr inner_dst = {0};
        if (offset_info->icmp_error_l3_protocol == LANDSCAPE_IPV4_TYPE) {
            struct iphdr *inner_iph;
            if (VALIDATE_READ_DATA(skb, &inner_iph, offset_info->icmp_error_l3_offset,
                                   sizeof(*inner_iph))) {
                return TC_ACT_SHOT;
            }
            inner_dst.ip = inner_iph->daddr;
        } else if (offset_info->icmp_error_l3_protocol == LANDSCAPE_IPV6_TYPE) {
            struct ipv6hdr *inner_ip6h;
            if (VALIDATE_READ_DATA(skb, &inner_ip6h, offset_info->icmp_error_l3_offset,
                                   sizeof(*inner_ip6h))) {
                return TC_ACT_SHOT;
            }
            COPY_ADDR_FROM(inner_dst.all, inner_ip6h->daddr.in6_u.u6_addr32);
        } else {
            return TC_ACT_UNSPEC;
        }

        struct inet_pair inner_pair = {0};
        ret = firewall_read_l4_info(skb, offset_info->icmp_error_l4_protocol,
                                    offset_info->icmp_error_inner_l4_offset, true, &inner_pair);
        if (ret != TC_ACT_OK) return ret;

        COPY_ADDR_FROM(ip_pair->src_addr.all, inner_dst.all);
        ip_pair->src_port = inner_pair.dst_port;
        ip_pair->dst_port = inner_pair.src_port;
        return TC_ACT_OK;
    }

    ret = firewall_read_l4_info(skb, offset_info->l4_protocol, offset_info->l4_offset, false,
                                ip_pair);
    if (ret != TC_ACT_OK) return ret;

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int extract_firewall_v4_packet_info(struct __sk_buff *skb,
                                                           struct packet_offset_info *offset_info,
                                                           struct inet_pair *ip_pair,
                                                           u32 current_l3_offset) {
    int ret = extract_firewall_packet_info(skb, offset_info, ip_pair, current_l3_offset);
    if (ret != TC_ACT_OK) return ret;
    return offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE ? TC_ACT_OK : TC_ACT_UNSPEC;
}

static __always_inline int extract_firewall_v6_packet_info(struct __sk_buff *skb,
                                                           struct packet_offset_info *offset_info,
                                                           struct inet_pair *ip_pair,
                                                           u32 current_l3_offset) {
    int ret = extract_firewall_packet_info(skb, offset_info, ip_pair, current_l3_offset);
    if (ret != TC_ACT_OK) return ret;
    return offset_info->l3_protocol == LANDSCAPE_IPV6_TYPE ? TC_ACT_OK : TC_ACT_UNSPEC;
}

#endif /* LD_FIREWALL_PACKET_H */
