#ifndef __LD_WAN_IP_H__
#define __LD_WAN_IP_H__
#include <bpf/bpf_helpers.h>



#define IPV6_WAN_ADDR_PREFIX_LEN 7
#define IPV6_WAN_ADDR_SUFFIX_LEN 16 - 7

struct wan_ip_info_key {
    u32 ifindex;
    u8 l3_protocol;
    u8 _pad[3];
};

struct wan_ip_info_value {
    // when IPV4, is IPv4 Address
    // when IPv6, ip IPv6 Prefix
    union u_inet_addr addr;
    // always Gateway
    union u_inet_addr gateway;
    // mask length
    u8 mask;
    u8 has_mac;
    u8 mac[6];
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct wan_ip_info_key);    // index
    __type(value, struct wan_ip_info_value);  // ipv4
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wan_ip_binding SEC(".maps");

#endif /* __LD_WAN_IP_H__ */