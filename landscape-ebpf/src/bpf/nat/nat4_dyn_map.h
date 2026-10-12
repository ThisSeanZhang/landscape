#ifndef __LD_NAT4_DYN_MAP_H__
#define __LD_NAT4_DYN_MAP_H__

#include "nat/nat_common.h"

#define NAT4_TIMER_SIZE NAT_MAPPING_TIMER_SIZE
#define NAT4_PORT_QUEUE_SIZE 65536

struct nat4_mapping_value_v3 {
    u64 state_ref;
    __be32 addr;
    __be32 trigger_addr;
    __be16 port;
    __be16 trigger_port;
    u16 generation;
    u8 _pad;
    u8 is_allow_reuse;
};

struct nat4_egress_mapping_value_v3 {
    __be32 addr;
    __be16 port;
    __be16 trigger_port;
    __be32 trigger_addr;
    u8 is_allow_reuse;
    u8 _pad[3];
};

struct nat4_port_queue_value_v3 {
    __be16 port;
    u16 last_generation;
};

struct nat4_timer_value_v3 {
    u64 server_status;
    u64 client_status;
    u64 status;
    struct bpf_timer timer;
    struct inet4_addr client_addr;
    u16 client_port;
    u8 gress;
    u8 flow_id;
    u64 create_time;
    u64 ingress_bytes;
    u64 ingress_packets;
    u64 egress_bytes;
    u64 egress_packets;
    u32 cpu_id;
    u32 ifindex;
    u16 generation_snapshot;
    u8 is_static;
    u8 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat4_mapping_key);
    __type(value, struct nat4_mapping_value_v3);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
} nat4_ingress_dyn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat4_mapping_key);
    __type(value, struct nat4_egress_mapping_value_v3);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
} nat4_egress_dyn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat4_timer_key);
    __type(value, struct nat4_timer_value_v3);
    __uint(max_entries, NAT4_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat4_timer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct nat4_port_queue_value_v3);
    __uint(max_entries, NAT4_PORT_QUEUE_SIZE);
} nat4_tcp_port_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct nat4_port_queue_value_v3);
    __uint(max_entries, NAT4_PORT_QUEUE_SIZE);
} nat4_udp_port_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct nat4_port_queue_value_v3);
    __uint(max_entries, NAT4_PORT_QUEUE_SIZE);
} nat4_icmp_port_queue SEC(".maps");

#endif /* __LD_NAT4_DYN_MAP_H__ */
