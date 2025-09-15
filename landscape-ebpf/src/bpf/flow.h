#ifndef __LD_FLOW_H__
#define __LD_FLOW_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"
#include "packet_def.h"
#include "flow_match.h"

enum flow_chache_type {
    PASS = 0,
    REDIRECT = 1,
};

struct flow_ip_cache_key {
    // 目标 IP 地址
    union u_inet_addr dst_addr;
    struct flow_match_key match_key;
};

// 准备删除 切换到使用 IP 进行匹配
struct old_flow_match_key {
    // 源 mac 地址
    unsigned char h_source[6];
    // vlan id
    u32 vlan_tci;
    // tos value
    u8 tos;
    u8 _pad;
};

// // 准备删除 切换到使用 IP 进行匹配
struct old_flow_cache_key {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    struct old_flow_match_key match_key;
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

struct flow_dns_match_key {
    union u_inet_addr addr;
    u8 l3_protocol;
    u8 _pad[3];
} __flow_dns_match_key;

struct flow_dns_match_value {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_dns_match_value;

// 每个流中特定的 DNS 规则
struct each_flow_dns {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    // __uint(key_size, 16);
    // __uint(map_flags, BPF_F_NO_COMMON_LRU);
    __type(key, struct flow_dns_match_key);
    __type(value, struct flow_dns_match_value);
    __uint(max_entries, 4096);
} each_flow_dns_map SEC(".maps");

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_dns);
} flow_v_dns_map SEC(".maps");

//
struct flow_ip_trie_key {
    __u32 prefixlen;
    u8 l3_protocol;
    u8 _pad[3];
    u8 addr[16];
} __flow_ip_trie_key;

struct flow_ip_trie_value {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_ip_trie_value;

// 每个流中特定的 目标 IP 规则
struct each_flow_ip_trie {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct flow_ip_trie_key);
    __type(value, struct flow_ip_trie_value);
    __uint(max_entries, 65536);
} each_flow_ip_map SEC(".maps");

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_ip_trie);
} flow_v_ip_map SEC(".maps");

struct lan_route_key {
    __u32 prefixlen;
    u8 l3_protocol;
    u8 _pad[3];
    struct in6_addr addr;
};

struct lan_route_info {
    bool has_mac;
    u8 mac_addr[6];
    u8 _pad[2];
    u32 ifindex;
    struct in6_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lan_route_key);
    __type(value, struct lan_route_info);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_lan_map SEC(".maps");

struct route_target_key {
    __u32 flow_id;
    u8 l3_protocol;
    u8 _pad[3];
};

struct route_context {
    struct in6_addr saddr;
    struct in6_addr daddr;
    // IP 协议: IPv4 Ipv6, LANDSCAPE_IPV4_TYPE | LANDSCAPE_IPV6_TYPE
    u8 l3_protocol;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    // tos value
    u8 tos;
    // TODO
    // u16 dst_port;
    u8 smac[6];
    u8 _pad[3];
};

struct route_target_info {
    u32 ifindex;
    struct in6_addr gate_addr;
    // 是否有 mac
    bool has_mac;
    bool is_docker;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_target_key);
    __type(value, struct route_target_info);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt_target_map SEC(".maps");

struct lan_mac_cache_key {
    u8 ip[16];
    u8 l3_protocol;
    u8 _pad[3];
};

struct lan_mac_cache {
    u8 mac[6];
    u8 _pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct lan_mac_cache_key);
    __type(value, struct lan_mac_cache);
    __uint(max_entries, 65535);
} ip_mac_tab SEC(".maps");

#endif /* __LD_FLOW_H__ */