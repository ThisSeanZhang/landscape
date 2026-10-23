#ifndef __LD_TPROXY_PACKET_H__
#define __LD_TPROXY_PACKET_H__

#include "base/landscape.h"
#include "base/proto_def.h"
#include "scanner/pkg_scanner.h"

static __always_inline int scan_tproxy_packet(struct __sk_buff *skb, u32 current_l3_offset,
                                              struct packet_offset_info *offset_info) {
    return scan_packet_full(skb, current_l3_offset, offset_info);
}

static __always_inline int read_tproxy_packet_info(struct __sk_buff *skb,
                                                   struct packet_offset_info *offset_info,
                                                   struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "read_tproxy_packet_info"

    if (offset_info->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, offset_info->l3_offset_when_scan, sizeof(struct iphdr))) {
            ld_bpf_log("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        ip_pair->dst_addr.in6_u.u6_addr32[0] = iph->daddr;
        ip_pair->src_addr.in6_u.u6_addr32[0] = iph->saddr;

        if (offset_info->icmp_error_l3_offset > 0) {
            if (VALIDATE_READ_DATA(skb, &iph, offset_info->icmp_error_l3_offset,
                                   sizeof(struct iphdr))) {
                ld_bpf_log("ipv4 bpf_skb_load_bytes error");
                return TC_ACT_SHOT;
            }
            ip_pair->src_addr.in6_u.u6_addr32[0] = iph->daddr;
        }
    } else if (offset_info->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->l3_offset_when_scan,
                               sizeof(struct ipv6hdr))) {
            ld_bpf_log("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        COPY_ADDR_FROM(ip_pair->src_addr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(ip_pair->dst_addr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);

        if (offset_info->icmp_error_l3_offset > 0) {
            if (VALIDATE_READ_DATA(skb, &ip6h, offset_info->icmp_error_l3_offset,
                                   sizeof(struct ipv6hdr))) {
                ld_bpf_log("ipv6 bpf_skb_load_bytes error");
                return TC_ACT_SHOT;
            }
            COPY_ADDR_FROM(ip_pair->src_addr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    if (offset_info->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, offset_info->icmp_error_inner_l4_offset,
                               sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->dst_port = tcph->source;
        ip_pair->src_port = tcph->dest;

        if (tcph->fin) {
            offset_info->pkt_type = PKT_TCP_FIN_V2;
        } else if (tcph->rst) {
            offset_info->pkt_type = PKT_TCP_RST_V2;
        } else if (tcph->syn) {
            offset_info->pkt_type = PKT_TCP_SYN_V2;
        } else {
            offset_info->pkt_type = PKT_TCP_DATA_V2;
        }
    } else if (offset_info->l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, offset_info->l4_offset, sizeof(*tcph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = tcph->source;
        ip_pair->dst_port = tcph->dest;

        if (tcph->fin) {
            offset_info->pkt_type = PKT_TCP_FIN_V2;
        } else if (tcph->rst) {
            offset_info->pkt_type = PKT_TCP_RST_V2;
        } else if (tcph->syn) {
            offset_info->pkt_type = PKT_TCP_SYN_V2;
        } else {
            offset_info->pkt_type = PKT_TCP_DATA_V2;
        }
    } else if (offset_info->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, offset_info->icmp_error_inner_l4_offset,
                               sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->dst_port = udph->source;
        ip_pair->src_port = udph->dest;
    } else if (offset_info->l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (VALIDATE_READ_DATA(skb, &udph, offset_info->l4_offset, sizeof(*udph))) {
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = udph->source;
        ip_pair->dst_port = udph->dest;
    } else if (offset_info->l4_protocol == IPPROTO_ICMP ||
               offset_info->l4_protocol == IPPROTO_ICMPV6) {
        u32 offset = offset_info->l4_offset;
        if (offset_info->icmp_error_inner_l4_offset > 0) {
            offset = offset_info->icmp_error_inner_l4_offset;
        }
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, offset, sizeof(struct icmphdr))) {
            return TC_ACT_SHOT;
        }

        ip_pair->src_port = ip_pair->dst_port = icmph->un.echo.id;
    } else {
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_TPROXY_PACKET_H__ */
