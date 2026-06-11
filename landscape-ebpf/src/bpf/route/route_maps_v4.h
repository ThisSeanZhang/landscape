#ifndef __LD_ROUTE_MAP_v4_H__
#define __LD_ROUTE_MAP_v4_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct lan_route_key_v4 {
    __u32 prefixlen;
    __be32 addr;
};

#define ROUTE_TYPE_LAN 0
#define ROUTE_TYPE_NEXTHOP 1
#define ROUTE_TYPE_WAN 2

struct lan_route_info_v4 {
    bool has_mac;
    u8 mac_addr[6];
    u8 route_type;
    u32 ifindex;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lan_route_key_v4);
    __type(value, struct lan_route_info_v4);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_lan_map SEC(".maps");

// reusable
struct flow_dns_match_value_v4 {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_dns_match_value_v4;

struct flow_dns_match_key_v4 {
    __be32 addr;
} __flow_dns_match_key_v4;

struct each_flow_dns_v4 {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct flow_dns_match_key_v4));
    __uint(value_size, sizeof(struct flow_dns_match_value_v4));
    __uint(max_entries, 4096);
};

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_dns_v4);
} flow4_dns_map SEC(".maps");

//
struct flow_ip_trie_key_v4 {
    __u32 prefixlen;
    __be32 addr;
} __flow_ip_trie_key_v4;

struct flow_ip_trie_value_v4 {
    u32 mark;
    u16 priority;
    u8 _pad[2];
} __flow_ip_trie_value_v4;

// 每个流中特定的 目标 IP 规则
struct each_flow_ip_trie_v4 {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(key_size, sizeof(struct flow_ip_trie_key_v4));
    __uint(value_size, sizeof(struct flow_ip_trie_value_v4));
    __uint(max_entries, 65536);
};

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_ip_trie_v4);
} flow4_ip_map SEC(".maps");

struct route_target_slot_key_v4 {
    __u32 flow_id;
    __u32 slot;
};

struct route_target_info_v4 {
    u32 ifindex;
    __be32 gate_addr;
    u8 has_mac;
    u8 is_docker;
    u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_target_slot_key_v4);
    __type(value, struct route_target_info_v4);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_target_slot_map SEC(".maps");

struct rt_cache_key_v4 {
    __be32 local_addr;
    __be32 remote_addr;
} _rt_cache_key_v4;

struct rt_cache_value_v4 {
    __u32 mark_value;
    u8 has_mac;
    u8 is_docker;
    u8 xdp_redirect_able;
    u8 _pad;
    __u32 ifindex;
    __be32 gate_addr;
    u8 mac[6];
    u8 l2_data[8];
} _rt_cache_value_v4;

// 缓存
struct each_v4_cache {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct rt_cache_key_v4));
    __uint(value_size, sizeof(struct rt_cache_value_v4));
    __uint(max_entries, 65536);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_v4_cache);
} rt4_cache_map SEC(".maps");

#endif /* __LD_ROUTE_MAP_v4_H__ */
