#ifndef __LD_ROUTE6_CACHE_H__
#define __LD_ROUTE6_CACHE_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "route/route_mode.h"

struct route6_cache_key {
    struct in6_addr local_addr;
    struct in6_addr remote_addr;
};

struct route6_cache_value {
    __u32 mark_value;
    u8 has_mac;
    u8 is_docker;
    u8 xdp_redirect_able;
    u8 _pad;
    __u32 ifindex;
    __u16 link_chain_id;
    u8 _pad_tail[2];
};

_Static_assert(sizeof(struct route6_cache_key) == 32, "route6_cache_key must be 32 bytes");
_Static_assert(sizeof(struct route6_cache_value) == 16, "route6_cache_value must be 16 bytes");
_Static_assert(__builtin_offsetof(struct route6_cache_value, link_chain_id) == 12,
               "route6_cache_value link_chain_id must be at offset 12");

// 缓存
struct route6_each_cache {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct route6_cache_key));
    __uint(value_size, sizeof(struct route6_cache_value));
    __uint(max_entries, 65536);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct route6_each_cache);
} rt6_cache_map SEC(".maps");

struct route6_conn_key {
    struct in6_addr saddr;
    struct in6_addr daddr;
    __be16 sport;
    __be16 dport;
    u8 l4_proto;
    u8 _pad[3];
} _route6_conn_key;

_Static_assert(sizeof(struct route6_conn_key) == 40, "route6_conn_key must be 40 bytes");

struct route6_each_conn {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct route6_conn_key));
    __uint(value_size, sizeof(struct route_conn_value));
    __uint(max_entries, 65536);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct route6_each_conn);
} rt6_conn_map SEC(".maps");

#endif /* __LD_ROUTE6_CACHE_H__ */
