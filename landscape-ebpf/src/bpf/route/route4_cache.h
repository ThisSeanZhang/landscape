#ifndef __LD_ROUTE4_CACHE_H__
#define __LD_ROUTE4_CACHE_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct route4_cache_key {
    __be32 local_addr;
    __be32 remote_addr;
};

struct route4_cache_value {
    __u32 mark_value;
    u8 has_mac;
    u8 is_docker;
    u8 xdp_redirect_able;
    u8 _pad;
    __u32 ifindex;
    __u16 link_chain_id;
    u8 _pad_tail[2];
};

_Static_assert(sizeof(struct route4_cache_key) == 8, "route4_cache_key must be 8 bytes");
_Static_assert(sizeof(struct route4_cache_value) == 16, "route4_cache_value must be 16 bytes");
_Static_assert(__builtin_offsetof(struct route4_cache_value, link_chain_id) == 12,
               "route4_cache_value link_chain_id must be at offset 12");

// 缓存
struct route4_each_cache {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct route4_cache_key));
    __uint(value_size, sizeof(struct route4_cache_value));
    __uint(max_entries, 65536);
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct route4_each_cache);
} rt4_cache_map SEC(".maps");

#endif /* __LD_ROUTE4_CACHE_H__ */
