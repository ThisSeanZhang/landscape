#ifndef __LD_ROUTE6_CACHE_H__
#define __LD_ROUTE6_CACHE_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"

struct route6_cache_key {
    union u_inet6_addr local_addr;
    union u_inet6_addr remote_addr;
} _route6_cache_key;

struct route6_cache_value {
    __u32 mark_value;
    u8 has_mac;
    u8 is_docker;
    u8 xdp_redirect_able;
    u8 _pad;
    __u32 ifindex;
    union u_inet6_addr gate_addr;
    u8 mac[6];
} _route6_cache_value;

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
    __uint(max_entries, 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct route6_each_cache);
} rt6_cache_map SEC(".maps");

#endif /* __LD_ROUTE6_CACHE_H__ */
