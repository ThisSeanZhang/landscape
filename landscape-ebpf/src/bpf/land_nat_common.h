#ifndef LD_NAT_COMMON_H
#define LD_NAT_COMMON_H
#include "landscape_log.h"
#include "landscape.h"
#include "pkg_def.h"

#define NAT_MAPPING_INGRESS 0
#define NAT_MAPPING_EGRESS 1

// 33333
volatile const __be16 TEST_PORT = 0x3582;

// 未建立连接时
const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
// TCP 超时时间
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;
// UDP 超时时间
const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;

// 检查间隔时间
const volatile u64 REPORT_INTERVAL = 1E9 * 5;

#define READ_SKB_U16(skb_ptr, offset, var)                                                         \
    do {                                                                                           \
        u16 *tmp_ptr;                                                                              \
        if (VALIDATE_READ_DATA(skb_ptr, &tmp_ptr, offset, sizeof(*tmp_ptr))) return TC_ACT_SHOT;   \
        var = *tmp_ptr;                                                                            \
    } while (0)

#define GRESS_MASK (1 << 0)

static __always_inline int bpf_write_port(struct __sk_buff *skb, int port_off, __be16 to_port) {
    return bpf_skb_store_bytes(skb, port_off, &to_port, sizeof(to_port), 0);
}

static __always_inline int is_handle_protocol(const u8 protocol) {
    // TODO mDNS
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP ||
        protocol == NEXTHDR_ICMP) {
        return TC_ACT_OK;
    } else {
        return TC_ACT_UNSPEC;
    }
}

struct nat_mapping_key {
    u8 gress;
    u8 l4proto;
    // egress: Cp
    // ingress: Np
    __be16 from_port;
    // egress: Ca
    // ingress: Na , maybe change to ifindex
    union u_inet_addr from_addr;
};

struct nat_mapping_key_v4 {
    u8 gress;
    u8 l4proto;
    // egress: Cp
    // ingress: Np
    __be16 from_port;
    // egress: Ca
    // ingress: Na , maybe change to ifindex
    __be32 from_addr;
};

struct nat_mapping_value_v4 {
    __be32 addr;
    // TODO： 触发这个关系的 ip 或者端口
    // 单独一张检查表， 使用这个 ip 获取是否需要检查
    __be32 trigger_addr;
    __be16 port;
    __be16 trigger_port;
    u8 is_static;
    u8 is_allow_reuse;
    u8 _pad[2];
    u64 active_time;
};

//
struct nat_timer_key {
    u8 l4proto;
    u8 _pad[3];
    // Ac:Pc_An:Pn
    struct inet4_pair pair_ip;
};

//
struct nat_timer_value {
    u64 server_status;
    u64 client_status;
    u64 status;
    struct bpf_timer timer;
    // As
    struct inet4_addr trigger_saddr;
    // Ps
    u16 trigger_port;
    u8 gress;
    u8 flow_id;

    u64 create_time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
};

//
struct nat_timer_key_v6 {
    u8 client_suffix[8];
    u16 client_port;
    u8 id_byte;
    u8 l4_protocol;
};

//
struct nat_timer_value_v6 {
    struct bpf_timer timer;
    u64 server_status;
    u64 client_status;
    u64 status;
    union inet6_addr trigger_addr;
    u16 trigger_port;
    u8 is_allow_reuse;
    u8 flow_id;

    u64 create_time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
    u8 client_prefix[8];
};

enum timer_status {
    TIMER_INIT = 0ULL,
    TIMER_ACTIVE = 20ULL,
    TIMER_TIMEOUT_1 = 30ULL,
    TIMER_TIMEOUT_2 = 31ULL,
    TIMER_RELEASE = 40ULL,
};

// 所能映射的范围
struct mapping_range {
    u16 start;
    u16 end;
};

// 用于搜寻可用的端口
struct search_port_ctx {
    struct nat_mapping_key ingress_key;
    struct mapping_range range;
    u16 remaining_size;
    // 小端序的端口
    u16 curr_port;
    bool found;
    u64 timeout_interval;
};

struct search_port_ctx_v4 {
    struct nat_mapping_key_v4 ingress_key;
    struct mapping_range range;
    u16 remaining_size;
    // 小端序的端口
    u16 curr_port;
    bool found;
    u64 timeout_interval;
};

static __always_inline bool pkt_allow_initiating_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS_V2 || pkt_type == PKT_TCP_SYN_V2;
}

#endif /* LD_NAT_COMMON_H */
