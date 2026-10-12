#ifndef __LD_PKG_DEF_H__
#define __LD_PKG_DEF_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include "base/landscape_log.h"
#include "base/landscape.h"

#define LD_IP_MF 0x2000      // IPv4 more-fragments flag
#define LD_IP_OFFSET 0x1FFF  // IPv4 fragment offset mask

// RFC 8200 要求支持至少 6 个扩展头
#define LD_MAX_IPV6_EXT_NUM 6

enum land_frag_type {
    FRAG_SINGLE = 0,
    FRAG_FIRST,
    FRAG_MIDDLE,
    FRAG_LAST,
};

#define CT_INIT 0
#define CT_SYN 1
#define CT_FIN 2
#define CT_LESS_EST 3

// IPv6 Next Header protocol numbers (RFC 8200 / IANA)
#define NEXTHDR_HOP 0
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_ICMP 58
#define NEXTHDR_NONE 59
#define NEXTHDR_DEST 60
#define NEXTHDR_SCTP 132

// IPv6 fragment header field masks (RFC 8200)
#define IPV6_FRAG_OFFSET 0xFFF8
#define IPV6_FRAG_MF 0x0001

// ICMPv4 type values (RFC 792; see <linux/icmp.h>)
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12
#define ICMP_TIMESTAMP 13
#define ICMP_TIMESTAMPREPLY 14

// ICMPv6 type values (RFC 4443; see <linux/icmpv6.h>)
#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

// connection type of a packet (PKT_*_V2) is defined in einat_types.h

struct route_context_test {
    union u_inet_addr saddr;
    union u_inet_addr daddr;
    // IP 协议: IPv4 Ipv6, LANDSCAPE_IPV4_TYPE | LANDSCAPE_IPV6_TYPE
    u8 l3_protocol;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    u8 _pad[1];
};

#define ICMP_HDR_LEN sizeof(struct icmphdr)
#define ICMP6_HDR_LEN sizeof(struct icmp6hdr)

static __always_inline void print_route_context(struct route_context_test *ctx) {
#define BPF_LOG_TOPIC "print_route_context"
    if (!ctx) return;

    ld_bpf_log("==== route_context ====");
    if (ctx->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        ld_bpf_log("IPv4");
        ld_bpf_log("saddr: %pI4", ctx->saddr.all);
        ld_bpf_log("daddr: %pI4", ctx->daddr.all);
    } else if (ctx->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        ld_bpf_log("IPv6");
        ld_bpf_log("saddr: %pI6", ctx->saddr.all);
        ld_bpf_log("daddr: %pI6", ctx->daddr.all);
    }
    ld_bpf_log("l3_protocol: %u", ctx->l3_protocol);
    ld_bpf_log("l4_protocol: %u", ctx->l4_protocol);
    ld_bpf_log("tos: %u", ctx->tos);
    // ld_bpf_log("smac: %02x:%02x:%02x:%02x:%02x:%02x",
    //              ctx->smac[0], ctx->smac[1], ctx->smac[2],
    //              ctx->smac[3], ctx->smac[4], ctx->smac[5]);
    ld_bpf_log("====================");
#undef BPF_LOG_TOPIC
}

/// 作为 fragment 缓存的 key
// struct fragment_cache_key {
//     u8 _pad[3];
//     u8 l4_protocol;
//     u32 id;
//     union u_inet_addr saddr;
//     union u_inet_addr daddr;
// };

// struct fragment_cache_value {
//     u16 sport;
//     u16 dport;
// };

static __always_inline int is_broadcast_ip_new(u8 l3_protocol, const union u_inet_addr *ip) {
    bool is_ipv6_broadcast = false;
    bool is_ipv6_locallink = false;
    bool is_ipv4_broadcast = false;

    if (l3_protocol == LANDSCAPE_IPV6_TYPE) {
        __u8 first_byte = ip->bits[0];

        // IPv6 multicast ff00::/8
        if (first_byte == 0xff) {
            is_ipv6_broadcast = true;
        }

        // IPv6 link-local fe80::/10
        if (first_byte == 0xfe) {
            __u8 second_byte = ip->bits[1];
            if ((second_byte & 0xc0) == 0x80) {  // top 2 bits == 10
                is_ipv6_locallink = true;
            }
        }

    } else if (l3_protocol == LANDSCAPE_IPV4_TYPE) {
        __be32 dst = ip->ip;

        // 255.255.255.255 or 0.0.0.0 (network byte order)
        if (dst == bpf_htonl(0xffffffff) || dst == 0) {
            is_ipv4_broadcast = true;
        }
    }

    if (is_ipv4_broadcast || is_ipv6_broadcast || is_ipv6_locallink) {
        return TC_ACT_UNSPEC;
    } else {
        return TC_ACT_OK;
    }
}

static __always_inline int is_broadcast_ip_pair(u8 l3_protocol, const struct inet_pair *ip_pair) {
    if (is_broadcast_ip_new(l3_protocol, &ip_pair->src_addr)) {
        return TC_ACT_UNSPEC;
    } else if (is_broadcast_ip_new(l3_protocol, &ip_pair->dst_addr)) {
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_OK;
}

#endif /* __LD_PKG_DEF_H__ */