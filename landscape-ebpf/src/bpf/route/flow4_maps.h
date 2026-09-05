#ifndef __LD_FLOW4_MAPS_H__
#define __LD_FLOW4_MAPS_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

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

#endif /* __LD_FLOW4_MAPS_H__ */
