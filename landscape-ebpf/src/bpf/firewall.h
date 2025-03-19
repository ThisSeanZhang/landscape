#ifndef __LD_FIREWALL_H__
#define __LD_FIREWALL_H__
#include <bpf/bpf_endian.h>

#include "vmlinux.h"
#include "landscape_log.h"
#include "landscape.h"

#define IPV4_EGRESS_PROG_INDEX 0
#define IPV4_INGRESS_PROG_INDEX 1
#define IPV6_EGRESS_PROG_INDEX 2
#define IPV6_INGRESS_PROG_INDEX 3

#define IP_MF bpf_htons(0x2000)     /* Flag: "More Fragments"	*/
#define IP_OFFSET bpf_htons(0x1FFF) /* "Fragment Offset" part	*/

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

const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
const volatile u64 TCP_TCP_TRANS = 1E9 * 60 * 4;
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;

const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;

// ICMPv4 消息类型
enum {
    ICMP_ERROR_MSG,
    ICMP_QUERY_MSG,
    ICMP_ACT_UNSPEC,
    ICMP_ACT_SHOT,
};

// ICMPv6 消息类型

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

union u_inet_addr {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
};

struct inet_pair {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

/// @brief 持有解析的 IP 信息
struct ip_context {
    u8 _pad;
    // ip 报文承载的协议类型: TCP / UDP / ICMP
    u8 ip_protocol;
    // 数据包的处理类型 (例如, 非链接, SYN FIN)
    u8 pkt_type;
    // 分片类型，例如 NOT_F、MORE_F、END_F
    u8 fragment_type;
    // 分片偏移量
    u16 fragment_off;
    // 当前分片 id 标识符
    u16 fragment_id;
    // IPv4 键值对
    struct inet_pair pair_ip;
};

/// @brief 数据包解析上下文
struct packet_context {
    struct ip_context ip_hdr;
    // l4 的负载偏移位置 当为 0 时表示没有 ip 的负载 也就是没有 TCP ICMP UDP 头部信息
    // 为 -1 表示为 IP 的分片
    int l4_payload_offset;
    // icmp 错误时指向 l4 的负载起始位置
    // 不为 0 表示 这个是 icmp 错误 包
    int icmp_error_payload_offset;
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

/// IP Fragment Related End

struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    struct in6_addr addr;
};

struct firewall_action {
    __u32 mark;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip6_map SEC(".maps");

// 检查是否开放连接的 key
struct firewall_conntrack_key {
    u8 ip_type;
    u8 ip_protocol;
    __be16 local_port;
    union u_inet_addr local_addr;
};

// 动态开放端口
struct firewall_conntrack_action {
    u64 status;
    union u_inet_addr trigger_addr;
    __be16 trigger_port;
    __be16 _pad;
    __u32 mark;
    struct bpf_timer timer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct firewall_conntrack_key);
    __type(value, struct firewall_conntrack_action);
    __uint(max_entries, 35565);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_conntrack_map SEC(".maps");

// ipv4 = 32 + 8 + 8 + 16 = 64
// ipv6 = 128 + 8 + 8 + 16 = 160
struct firewall_static_rule_key {
    __u32 prefixlen;
    u8 ip_type;
    u8 ip_protocol;
    __be16 local_port;
    union u_inet_addr remote_address;
};

// 静态配置开放端口
struct firewall_static_ct_action {
    union u_inet_addr trigger_addr;
    __be16 trigger_port;
    __be16 _pad;
    __u32 mark;
};

// local_port + TRIE remote ip
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct firewall_static_rule_key);
    __type(value, struct firewall_static_ct_action);
    __uint(max_entries, 35565);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_static_ct_map SEC(".maps");
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
#endif /* __LD_FIREWALL_H__ */