#ifndef __LD_PKG_DEF_H__
#define __LD_PKG_DEF_H__

#include <bpf/bpf_endian.h>
#include "landscape_log.h"
#include "landscape.h"

#define LD_IP_MF bpf_htons(0x2000)     /* Flag: "More Fragments"	*/
#define LD_IP_OFFSET bpf_htons(0x1FFF) /* "Fragment Offset" part	*/

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

// Timer 创建情况
enum { TIMER_EXIST, TIMER_NOT_FOUND, TIMER_ERROR, TIMER_CREATED };

/*
 *	NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP 0       /* Hop-by-hop option header. */
#define NEXTHDR_ROUTING 43  /* Routing header. */
#define NEXTHDR_FRAGMENT 44 /* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH 51     /* Authentication header. */
#define NEXTHDR_DEST 60     /* Destination options header. */

#define NEXTHDR_TCP 6    /* TCP segment. */
#define NEXTHDR_UDP 17   /* UDP message. */
#define NEXTHDR_ICMP 58  /* ICMP for IPv6. */
#define NEXTHDR_NONE 59  /* No next header */
#define NEXTHDR_SCTP 132 /* SCTP message. */

#define IPV6_FRAG_OFFSET 0xFFF8
#define IPV6_FRAG_MF 0x0001

// #include <linux/icmp.h>
#define ICMP_DEST_UNREACH 3   /* Destination Unreachable	*/
#define ICMP_TIME_EXCEEDED 11 /* Time Exceeded		*/
#define ICMP_PARAMETERPROB 12 /* Parameter Problem		*/

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/

#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

// 数据包所属的连接类型
enum {
    // 无连接
    PKT_CONNLESS_V2,
    //
    PKT_TCP_DATA_V2,
    PKT_TCP_SYN_V2,
    PKT_TCP_RST_V2,
    PKT_TCP_FIN_V2,
    PKT_TCP_ACK_V2,
};

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

static __always_inline void print_route_context(struct route_context_test *ctx) {
#define BPF_LOG_TOPIC "print_route_context"
    if (!ctx) return;

    bpf_log_info("==== route_context ====");
    if (ctx->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        bpf_log_info("IPv4");
        bpf_log_info("saddr: %pI4", ctx->saddr.all);
        bpf_log_info("daddr: %pI4", ctx->daddr.all);
    } else if (ctx->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        bpf_log_info("IPv6");
        bpf_log_info("saddr: %pI6", ctx->saddr.all);
        bpf_log_info("daddr: %pI6", ctx->daddr.all);
    }
    bpf_log_info("l3_protocol: %u", ctx->l3_protocol);
    bpf_log_info("l4_protocol: %u", ctx->l4_protocol);
    bpf_log_info("tos: %u", ctx->tos);
    // bpf_log_info("smac: %02x:%02x:%02x:%02x:%02x:%02x",
    //              ctx->smac[0], ctx->smac[1], ctx->smac[2],
    //              ctx->smac[3], ctx->smac[4], ctx->smac[5]);
    bpf_log_info("====================");
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