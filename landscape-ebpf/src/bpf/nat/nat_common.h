#ifndef LD_NAT_COMMON_H
#define LD_NAT_COMMON_H
#include <vmlinux.h>
#include "../landscape_log.h"
#include "../landscape.h"
#include "../pkg_def.h"

#define NAT_MAPPING_CACHE_SIZE 1024 * 64 * 2
#define NAT_MAPPING_TIMER_SIZE 1024 * 64 * 2

#define NAT_MAPPING_INGRESS 0
#define NAT_MAPPING_EGRESS 1

#define NAT_CONN_ACTIVE 1
#define NAT_CONN_DELETE 2

// 33333
volatile const __be16 TEST_PORT = 0x3582;

#ifndef LD_CONN_TIMEOUTS_DEFINED
#define LD_CONN_TIMEOUTS_DEFINED
// 未建立连接时
const volatile u64 TCP_SYN_TIMEOUT = 1E9 * 6;
// TCP 超时时间
const volatile u64 TCP_TIMEOUT = 1E9 * 60 * 10;
// UDP 超时时间
const volatile u64 UDP_TIMEOUT = 1E9 * 60 * 5;
#endif

// 检查间隔时间
const volatile u64 REPORT_INTERVAL = 1E9 * 5;

#define READ_SKB_U16(skb_ptr, offset, var)                                                         \
    do {                                                                                           \
        u16 *tmp_ptr;                                                                              \
        if (VALIDATE_READ_DATA(skb_ptr, &tmp_ptr, offset, sizeof(*tmp_ptr))) return TC_ACT_SHOT;   \
        var = *tmp_ptr;                                                                            \
    } while (0)

#define GRESS_MASK (1 << 0)

static __always_inline bool should_nat_skip_protocol(const u8 protocol) {
    return !(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP ||
             protocol == NEXTHDR_ICMP);
}

struct nat4_mapping_key {
    u8 gress;
    u8 l4proto;
    // egress: Cp
    // ingress: Np
    __be16 from_port;
    // egress: Ca
    // ingress: Na
    __be32 from_addr;
};

struct nat4_timer_key {
    u8 l4proto;
    u8 _pad[3];
    // As:Ps_An:Pn
    struct inet4_pair pair_ip;
};

//
struct nat6_timer_key {
    u8 client_suffix[8];
    u16 client_port;
    u8 id_byte;
    u8 l4_protocol;
};

//
struct nat6_timer_value {
    struct bpf_timer timer;
    u64 server_status;
    u64 client_status;
    u64 status;
    inet6_addr trigger_addr;
    u16 trigger_port;
    u8 is_allow_reuse;
    u8 flow_id;
    u8 gress;
    u8 is_static;
    u8 need_prefix_replace;
    u8 _pad;

    u64 create_time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
    u32 cpu_id;
    u32 ifindex;
    u8 client_prefix[8];
};

enum timer_status {
    TIMER_INIT = 0ULL,
    TIMER_PENDING_REF = 10ULL,
    TIMER_ACTIVE = 20ULL,
    TIMER_TIMEOUT_1 = 30ULL,
    TIMER_TIMEOUT_2 = 31ULL,
    TIMER_RELEASE = 40ULL,
    TIMER_CLEAN_START = 50ULL,
    TIMER_DELETE_EGRESS = TIMER_CLEAN_START,
    TIMER_DELETE_INGRESS = 51ULL,
    TIMER_PUSH_QUEUE = 52ULL,
};

// Generic success/error result for NAT helper functions.
// Non-zero on error so `if (nat_helper())` keeps meaning "failed".
enum nat_op_result {
    NAT_OP_OK = 0,
    NAT_OP_ERR = -1,
};

// Result of an IPv6 static mapping lookup.
enum nat6_static_result {
    NAT6_STATIC_MISS = 0,     // no static mapping, fall back to dynamic path
    NAT6_STATIC_REPLACE = 1,  // static mapping hit, client prefix must be replaced
    NAT6_STATIC_PASS = 2,     // static mapping hit, no prefix replace needed
};

static __always_inline bool pkt_can_begin_ct(u8 pkt_type) {
    return pkt_type == PKT_CONNLESS_V2 || pkt_type == PKT_TCP_SYN_V2;
}

static __always_inline bool ct_try_set_status(u64 *status_in_value, u64 curr_state,
                                              u64 next_state) {
    return __sync_bool_compare_and_swap(status_in_value, curr_state, next_state);
}

static __always_inline bool ct_status_can_activate(u64 status) {
    return status != TIMER_ACTIVE && status != TIMER_PENDING_REF && status < TIMER_CLEAN_START;
}

struct nat4_action {
    struct inet4_addr from_addr;
    __be16 from_port;
    struct inet4_addr to_addr;
    __be16 to_port;
};

struct nat4_egress_result {
    __be32 nat_addr;
    __be16 nat_port;
    u8 is_created;
    u8 _pad;
};

struct nat4_static_value {
    __be32 addr;
    __be16 port;
    u8 _pad[2];
};

struct nat4_lan_result {
    __be32 lan_addr;
    __be16 lan_port;
    u8 _pad[2];
};

#endif /* LD_NAT_COMMON_H */
