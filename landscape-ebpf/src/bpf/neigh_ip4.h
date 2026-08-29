#ifndef __LD_IP_NEIGH4_H__
#define __LD_IP_NEIGH4_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

struct mac_key_v4 {
    __be32 addr;
};

struct mac_value_v4 {
    u32 ifindex;
    u8 mac[6];
    u8 dev_mac[6];
    __be16 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct mac_key_v4);
    __type(value, struct mac_value_v4);
    __uint(max_entries, 4096);
} ip_mac_v4 SEC(".maps");

#endif /* __LD_IP_NEIGH4_H__ */
