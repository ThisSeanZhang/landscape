#ifndef __LD_FIREWALL_SHARE_H__
#define __LD_FIREWALL_SHARE_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

// ipv4 = 32 + 8 + 8 + 16 = 64
// ipv6 = 128 + 8 + 8 + 16 = 160
struct firewall_static_rule_key {
    __u32 prefixlen;
    // l3_proto
    u8 ip_type;
    // l4_proto
    u8 ip_protocol;
    __be16 local_port;
    union u_inet_addr remote_address;
};

// 静态配置开放端口
struct firewall_static_ct_action {
    __u32 mark;
};

/// IP Fragment Related End
struct firewall_action {
    __u32 mark;
};

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

#define FIREWALL_CREATE_CONN 1
#define FIREWALL_DELETE_CONN 2
struct firewall_conn_event {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    u16 src_port;
    u16 dst_port;
    u64 create_time;
    u64 report_time;
    u8 l4_proto;
    u8 l3_proto;
    u8 event_type;
    u8 flow_id;
    u8 trace_id;
} __firewall_conn_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} firewall_conn_events SEC(".maps");

struct firewall_conn_metric_event {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    u16 src_port;
    u16 dst_port;
    u64 create_time;
    u64 time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
    u8 l4_proto;
    u8 l3_proto;
    u8 flow_id;
    u8 trace_id;
} __firewall_conn_metric_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} firewall_conn_metric_events SEC(".maps");

#endif /* __LD_FIREWALL_SHARE_H__ */