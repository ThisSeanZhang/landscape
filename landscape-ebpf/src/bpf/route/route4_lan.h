#ifndef __LD_ROUTE4_LAN_H__
#define __LD_ROUTE4_LAN_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "route_common.h"

struct route4_lan_key {
    __u32 prefixlen;
    __be32 addr;
};

struct route4_lan_info {
    bool has_mac;
    u8 mac_addr[6];
    u8 route_type;
    u32 ifindex;
    __be32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct route4_lan_key);
    __type(value, struct route4_lan_info);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt4_lan_map SEC(".maps");

#endif /* __LD_ROUTE4_LAN_H__ */
