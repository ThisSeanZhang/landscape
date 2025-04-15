#ifndef __LD_FLOW_H__
#define __LD_FLOW_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"
#include "packet_def.h"

enum flow_chache_type {
    PASS = 0,
    REDIRECT = 1,
};

struct flow_ip_match_key {
    // 源 IP 地址
    union u_inet_addr src_addr;
    // vlan id
    u32 vlan_tci;
    // tos value
    u8 tos;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // IP 协议: IPv4 Ipv6
    u8 l3_protocol;
    u8 _pad;
};

struct flow_ip_cache_key {
    // 目标 IP 地址
    union u_inet_addr dst_addr;
    struct flow_ip_match_key match_key;
};

// 准备删除 切换到使用 IP 进行匹配
struct flow_match_key {
    // 源 mac 地址
    unsigned char h_source[6];
    // vlan id
    u32 vlan_tci;
    // tos value
    u8 tos;
    u8 _pad;
};

// 准备删除 切换到使用 IP 进行匹配
struct flow_cache_key {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    struct flow_match_key match_key;
};

struct flow_target_info {
    // 目标 index
    u32 ifindex;
    // 是否有 mac
    bool has_mac;
    bool is_docker;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);                        // flow_id
    __type(value, struct flow_target_info);  // target ifindex
    __uint(max_entries, 2048);
} flow_target_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_ip_match_key);
    __type(value, u32);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_match_map SEC(".maps");

// struct each_flow_target {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
//     __type(key, u32);
//     __type(value, struct flow_target_info);
//     __uint(max_entries, 2048);
// } each_flow_target_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//     __type(key, u32);
//     __uint(max_entries, 512);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
//     __array(values, struct each_flow_target);
// } flow_target_map SEC(".maps");

struct flow_mark {
    u16 trace_id;
    u8 flow_action;
    u8 flow_id;
} __attribute__((packed));

// struct flow_dns_match_key {
//     union u_inet_addr addr;
// };

// 使用时出现   libbpf: map 'flow_v_dns_map.inner': can't determine key size for type [115]: -22.
// 每个流中特定的 DNS 规则
// struct each_flow_dns {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(key_size, 16);
//     // __type(key, struct flow_dns_match_key);
//     __type(value, u32);
//     __uint(max_entries, 2048);
// } each_flow_dns_map SEC(".maps");

// // flow <-> 对应规则 map
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//     __type(key, u32);
//     __uint(max_entries, 512);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
//     __array(values, struct each_flow_dns);
// } flow_v_dns_map SEC(".maps");

struct flow_dns_match_key {
    u32 flow_id;
    union u_inet_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_dns_match_key);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(value, u32);
} flow_v_dns_map SEC(".maps");

#endif /* __LD_FLOW_H__ */