#ifndef __LD_FLOW_MATCH_H__
#define __LD_FLOW_MATCH_H__
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "packet_def.h"
#include "landscape.h"

// 64 + 32 = 96
// 64 + 128 = 192
struct flow_match_key {
    u32 prefixlen;
    // vlan id
    u32 vlan_tci;
    // tos value
    u8 tos;
    // IP 协议: IPv4 Ipv6
    u8 l3_protocol;
    // IP 层协议: TCP / UDP
    u8 l4_protocol;
    u8 _pad;
    // 源 IP 地址
    union u_inet_addr src_addr;
};


struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct flow_match_key);
    __type(value, u32);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
} flow_match_map SEC(".maps");

#endif /* __LD_FLOW_MATCH_H__ */