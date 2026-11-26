#ifndef __LD_NAT6_DYN_MAP_H__
#define __LD_NAT6_DYN_MAP_H__

#include "nat/nat_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat6_timer_key);
    __type(value, struct nat6_timer_value);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat6_timer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat6_mapping_key);
    __type(value, struct nat6_mapping_value);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat6_mapping_map SEC(".maps");

/* Every caller owns one reference. Only the 1 -> 0 winner can delete this key. */
static __always_inline void nat6_mapping_put(const struct nat6_mapping_key *key,
                                             struct nat6_mapping_value *mapping) {
    bpf_spin_lock(&mapping->lock);
    bool last = --mapping->refs == 0;
    bpf_spin_unlock(&mapping->lock);
    if (last) bpf_map_delete_elem(&nat6_mapping_map, key);
}

#endif /* __LD_NAT6_DYN_MAP_H__ */
