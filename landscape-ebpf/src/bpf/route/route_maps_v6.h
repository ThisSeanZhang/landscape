#ifndef __LD_ROUTE_MAP_V6_H__
#define __LD_ROUTE_MAP_V6_H__
#include "vmlinux_wrapper.h"
#include <bpf/bpf_helpers.h>
#include "../landscape.h"

struct lan_route_key_v6 {
    __u32 prefixlen;
    union u_inet6_addr addr;
};

// TODO: define as flag
struct lan_route_info_v6 {
    bool has_mac;
    u8 mac_addr[6];
    // 0: current 1: next hop
    bool is_next_hop;
    // u8 _pad[1];
    u32 ifindex;
    union u_inet6_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lan_route_key_v6);
    __type(value, struct lan_route_info_v6);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt6_lan_map SEC(".maps");

// reusable
struct flow_dns_match_value_v6 {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_dns_match_value_v6;

struct flow_dns_match_key_v6 {
    union u_inet6_addr addr;
} __flow_dns_match_key_v6;

struct each_flow_dns_v6 {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    // __uint(key_size, 16);
    // __uint(map_flags, BPF_F_NO_COMMON_LRU);
    __type(key, struct flow_dns_match_key_v6);
    __type(value, struct flow_dns_match_value_v6);
    __uint(max_entries, 4096);
};

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_dns_v6);
} flow6_dns_map SEC(".maps");

//
struct flow_ip_trie_key_v6 {
    __u32 prefixlen;
    union u_inet6_addr addr;
} __flow_ip_trie_key_v6;

struct flow_ip_trie_value_v6 {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_ip_trie_value_v6;

// 每个流中特定的 目标 IP 规则
struct each_flow_ip_trie_v6 {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct flow_ip_trie_key_v6);
    __type(value, struct flow_ip_trie_value_v6);
    __uint(max_entries, 65536);
};

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_ip_trie_v6);
} flow6_ip_map SEC(".maps");

struct route_target_key_v6 {
    __u32 flow_id;
};

struct route_target_info_v6 {
    u32 ifindex;
    union u_inet6_addr gate_addr;
    u8 has_mac;
    u8 is_docker;
    u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_target_key_v6);
    __type(value, struct route_target_info_v6);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt6_target_map SEC(".maps");

struct rt_cache_key_v6 {
    union u_inet6_addr local_addr;
    union u_inet6_addr remote_addr;
} _rt_cache_key_v6;

struct rt_cache_value_v6 {
    union {
        __u32 mark_value;
        __u32 ifindex;
    };
    u8 has_mac;
} _rt_cache_value_v6;

// 缓存
struct each_v6_cache {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct rt_cache_key_v6);
    __type(value, struct rt_cache_value_v6);
    __uint(max_entries, 65536);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_v6_cache);
} rt6_cache_map SEC(".maps");

#endif /* __LD_ROUTE_MAP_V6_H__ */