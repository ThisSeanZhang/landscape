#ifndef __LD_PACKET_DEF_H__
#define __LD_PACKET_DEF_H__
#include "vmlinux.h"
#include "landscape_log.h"

#define IP_MF bpf_htons(0x2000)     /* Flag: "More Fragments"	*/
#define IP_OFFSET bpf_htons(0x1FFF) /* "Fragment Offset" part	*/

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

#define CLOCK_MONOTONIC 1

// RFC 8200 要求支持至少 6 个扩展头
#define MAX_IPV6_EXT_NUM 6

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

#undef BPF_LOG_TOPIC

#define ICMP_HDR_LEN sizeof(struct icmphdr)

#define LANDSCAPE_IPV4_TYPE 0
#define LANDSCAPE_IPV6_TYPE 1

union u_inet_addr {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bits[16];
};

struct inet_pair {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

// ICMPv4 消息类型
enum {
    ICMP_ERROR_MSG,
    ICMP_QUERY_MSG,
    ICMP_ACT_UNSPEC,
    ICMP_ACT_SHOT,
};

enum fragment_type {
    // 还有分片
    // offect 且 more 被设置
    MORE_F,
    // 结束分片
    // offect 的值不为 0
    END_F,
    // 没有分片
    NOT_F
};

// 数据包所属的连接类型
enum {
    // 无连接
    PKT_CONNLESS,
    //
    PKT_TCP_DATA,
    PKT_TCP_SYN,
    PKT_TCP_RST,
    PKT_TCP_FIN,
};

/// 作为 fragment 缓存的 key
struct fragment_cache_key {
    u8 _pad[3];
    u8 l4proto;
    u32 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct fragment_cache_value {
    u16 sport;
    u16 dport;
};

// Timer 状态
enum {
    TIMER_INIT = 0ULL,  // 0ULL ensures the value is of type u64
    TCP_SYN = 1ULL,
    TCP_SYN_ACK = 2ULL,
    TCP_EST = 3ULL,
    OTHER_EST = 4ULL
};
// Timer 创建情况
enum { TIMER_EXIST, TIMER_NOT_FOUND, TIMER_ERROR, TIMER_CREATED };

#define COPY_ADDR_FROM(t, s) (__builtin_memcpy((t), (s), sizeof(t)))

static __always_inline bool ip_addr_equal(const union u_inet_addr *a, const union u_inet_addr *b) {
    return a->all[0] == b->all[0] && a->all[1] == b->all[1] && a->all[2] == b->all[2] &&
           a->all[3] == b->all[3];
}

#endif /* __LD_PACKET_DEF_H__ */