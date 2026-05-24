#ifndef __LD_FRAG_COMMON_H__
#define __LD_FRAG_COMMON_H__

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "../pkg_def.h"

#define FRAG_CACHE_SIZE (1024 * 32)

struct frag_cache_key {
    u8 l3proto;
    u8 l4proto;
    u16 _pad;
    u32 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct frag_cache_value {
    u16 sport;
    u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct frag_cache_key);
    __type(value, struct frag_cache_value);
    __uint(max_entries, FRAG_CACHE_SIZE);
} frag_cache SEC(".maps");

#endif /* __LD_FRAG_COMMON_H__ */
