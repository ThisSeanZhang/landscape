#ifndef __LD_FIREWALL_SHARE_H__
#define __LD_FIREWALL_SHARE_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"
#include "firewall.h"

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct firewall_action);
    __uint(max_entries, 65535);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_block_ip6_map SEC(".maps");

// local_port + TRIE remote ip
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct firewall_static_rule_key);
    __type(value, struct firewall_static_ct_action);
    __uint(max_entries, 35565);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} firewall_allow_rules_map SEC(".maps");

#endif /* __LD_FIREWALL_SHARE_H__ */