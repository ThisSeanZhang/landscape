#ifndef __LD_FIREWALL_v2_H__
#define __LD_FIREWALL_v2_H__
#include <bpf/bpf_endian.h>

#include "vmlinux.h"
#include "landscape_log.h"
#include "landscape.h"
#include "pkg_scanner.h"
#include "pkg_fragment.h"

const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
const volatile u64 TCP_TCP_TRANS = 1E9 * 60 * 4;
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;

const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;

const volatile u64 CONN_EST_TIMEOUT = 1E9 * 5;
const volatile u64 CONN_TCP_RELEASE = 1E9 * 60 * 10;
const volatile u64 CONN_UDP_RELEASE = 1E9 * 60 * 5;

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


static __always_inline int is_handle_protocol(const u8 protocol) {
    // TODO mDNS
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP ||
        protocol == NEXTHDR_ICMP) {
        return TC_ACT_OK;
    } else {
        return TC_ACT_UNSPEC;
    }
}

#endif /* __LD_FIREWALL_v2_H__ */