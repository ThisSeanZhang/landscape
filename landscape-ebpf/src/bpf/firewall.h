#ifndef __LD_FIREWALL_H__
#define __LD_FIREWALL_H__
#include <bpf/bpf_endian.h>

#include "landscape_log.h"
#include "landscape.h"
#include "pkg_def.h"

#define IPV4_FIREWALL_EGRESS_PROG_INDEX 0
#define IPV4_FIREWALL_INGRESS_PROG_INDEX 0
#define IPV6_FIREWALL_EGRESS_PROG_INDEX 1
#define IPV6_FIREWALL_INGRESS_PROG_INDEX 1

const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
const volatile u64 TCP_TCP_TRANS = 1E9 * 60 * 4;
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;

const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;

const volatile u64 CONN_EST_TIMEOUT = 1E9 * 5;
const volatile u64 CONN_TCP_RELEASE = 1E9 * 60 * 10;
const volatile u64 CONN_UDP_RELEASE = 1E9 * 60 * 5;

// struct pkg_offset_info {
//     // ICMP Type
//     u8 icmp_type;
//     // ip 报文承载的协议类型: TCP / UDP / ICMP
//     u8 ip_protocol;
//     // 数据包的处理类型 (例如, 非链接, SYN FIN)
//     u8 pkt_type;
//     // 是否还有分片
//     u8 fragment_type;
//     // 分片偏移量
//     u16 fragment_off;
//     // 当前分片 id
//     u16 fragment_id;
//     // l3 的负载偏移位置 当为 0 时表示没有 ip 的负载 也就是没有 TCP ICMP UDP 头部信息
//     // 为 0 表示为 IP 的分片
//     u16 l4_payload_offset;
//     // icmp 错误时 icmp payload 的负载位置
//     // 不为 0 表示 这个是 icmp 错误 包
//     u16 icmp_inner_l4_offset;
// };

/// @brief 持有解析的 IP 信息
struct ip_context {
    // ip 报文承载的协议类型: TCP / UDP / ICMP
    u8 ip_protocol;
    // 数据包的处理类型 (例如, 非链接, SYN FIN)
    u8 pkt_type;
    // ICMP Type
    u8 icmp_type;
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

/// IP Fragment Related End
struct firewall_action {
    __u32 mark;
};

// 检查是否开放连接的 key
struct firewall_conntrack_key {
    // IPV4 / 6
    u8 ip_type;
    // TCP UDP ICMP
    u8 ip_protocol;
    __be16 local_port;
    union u_inet_addr local_addr;
};

// 动态开放端口
struct firewall_conntrack_action {
    u64 status;
    union u_inet_addr trigger_addr;
    __be16 trigger_port;
    __u8 flow_id;
    __u8 _pad;
    __u32 mark;
    struct bpf_timer timer;
    u64 create_time;
    u64 last_upload_ts;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
};

struct firewall_conntrack_action_v2 {
    u64 conn_status;
    union u_inet_addr trigger_addr;
    __be16 trigger_port;
    __u8 flow_id;
    __u8 _pad;
    __u32 mark;
    struct bpf_timer timer;
    u32 local_status;
    u32 remote_status;
    u64 create_time;
    u64 last_upload_ts;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct firewall_conntrack_key);
    __type(value, struct firewall_conntrack_action_v2);
    __uint(max_entries, 35565);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} fire2_conn_map SEC(".maps");

// ipv4 = 32 + 8 + 8 + 16 = 64
// ipv6 = 128 + 8 + 8 + 16 = 160
struct firewall_static_rule_key {
    __u32 prefixlen;
    // l3_proto
    u8 ip_type;
    // l4_proto
    u8 ip_protocol;
    __be16 local_port;
    union u_inet_addr remote_address;
};

// 静态配置开放端口
struct firewall_static_ct_action {
    __u32 mark;
};

enum firewall_report_status {
    FIREWALL_REPORT_NONE = 0,      // 没到时间，不需要上报
    FIREWALL_REPORT_SUCCESS = 1,   // 成功上报（且完成清理）
    FIREWALL_REPORT_CONFLICT = 2   // 到了时间，但 CAS 没成功，没争夺到上报权
};

enum connect_status {
    CONN_CLOSED = 0ULL,
    CONN_TCP_SYN = 1ULL,
    CONN_TCP_SYN_ACK = 2ULL,
    CONN_TCP_FIN = 3ULL,
    CONN_TCP_FIN_ACK = 4ULL,
    CONN_UDP_EST = 5ULL,
};

enum firewall_connect_status {
    FIREWALL_INIT = 0ULL,
    FIREWALL_ACTIVE = 20ULL,
    FIREWALL_TIMEOUT_1 = 30ULL,
    FIREWALL_TIMEOUT_2 = 31ULL,
    FIREWALL_RELEASE = 40ULL,
};
#endif /* __LD_FIREWALL_H__ */