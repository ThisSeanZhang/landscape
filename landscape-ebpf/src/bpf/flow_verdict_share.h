#ifndef __LD_FLOW_VERDICT_SHARE_H__
#define __LD_FLOW_VERDICT_SHARE_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"
#include "flow.h"
#include "packet_def.h"

// 每个流中特定的 目标 IP 规则
struct each_flow_ip_tire {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    __type(value, u32);
    __uint(max_entries, 65536);
} each_flow_ip_map SEC(".maps");

// flow <-> 对应规则 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u32);
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct each_flow_ip_tire);
} flow_v_ip_map SEC(".maps");

#endif /* __LD_FLOW_VERDICT_SHARE_H__ */