#ifndef __LD_NAT4_STATIC_H__
#define __LD_NAT4_STATIC_H__

#include "nat/nat_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat4_mapping_key);
    __type(value, struct nat4_static_value);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat4_static_map SEC(".maps");

#endif /* __LD_NAT4_STATIC_H__ */
