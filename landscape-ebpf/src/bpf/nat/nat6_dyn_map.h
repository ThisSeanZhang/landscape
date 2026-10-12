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

#endif /* __LD_NAT6_DYN_MAP_H__ */
