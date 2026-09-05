#ifndef __LD_ROUTE6_LAN_H__
#define __LD_ROUTE6_LAN_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "route_common.h"

struct route6_lan_key {
    __u32 prefixlen;
    union u_inet6_addr addr;
};

struct route6_lan_info {
    bool has_mac;
    u8 mac_addr[6];
    u8 route_type;
    u32 ifindex;
    union u_inet6_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct route6_lan_key);
    __type(value, struct route6_lan_info);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt6_lan_map SEC(".maps");

#endif /* __LD_ROUTE6_LAN_H__ */
