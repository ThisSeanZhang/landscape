#ifndef __LD_NAT6_STATIC_H__
#define __LD_NAT6_STATIC_H__

#include "nat_common.h"

#define STATIC_NAT_MAPPING_CACHE_SIZE 1024 * 64

struct static_nat6_mapping_key {
    __be16 port;
    u8 l4_protocol;
    u8 _pad;
    u8 ip_suffix[8];
};

struct static_nat6_mapping_value {
    u8 lan_prefix[8];
    u8 _pad[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct static_nat6_mapping_key);
    __type(value, struct static_nat6_mapping_value);
    __uint(max_entries, STATIC_NAT_MAPPING_CACHE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat6_static_map SEC(".maps");

#endif /* __LD_NAT6_STATIC_H__ */
