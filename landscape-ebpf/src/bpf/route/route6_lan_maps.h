#ifndef __LD_ROUTE6_LAN_MAPS_H__
#define __LD_ROUTE6_LAN_MAPS_H__
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../landscape.h"

struct lan_route_key_v6 {
    __u32 prefixlen;
    union u_inet6_addr addr;
};

#define ROUTE_TYPE_LAN 0
#define ROUTE_TYPE_NEXTHOP 1
#define ROUTE_TYPE_WAN 2

struct lan_route_info_v6 {
    bool has_mac;
    u8 mac_addr[6];
    u8 route_type;
    u32 ifindex;
    union u_inet6_addr addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lan_route_key_v6);
    __type(value, struct lan_route_info_v6);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rt6_lan_map SEC(".maps");

#endif /* __LD_ROUTE6_LAN_MAPS_H__ */
