#ifndef __LD_NAT_STATIC_H__
#define __LD_NAT_STATIC_H__
#include <bpf/bpf_helpers.h>

#include <vmlinux.h>
#include "../landscape.h"
#include "../land_nat_common.h"

#define STATIC_NAT_MAPPING_CACHE_SIZE 1024 * 64
#define NAT_MAPPING_CACHE_SIZE 1024 * 64 * 2
#define NAT_MAPPING_TIMER_SIZE 1024 * 64 * 2

struct static_nat_mapping_key_v6 {
    u32 prefixlen;
    // INGRESS: NAT Mapping Port
    // EGRESS: lan Clinet Port
    u16 port;
    u8 gress;
    u8 l3_protocol;
    u8 l4_protocol;
    u8 _pad[3];
    // INGRESS:  only use u32 for ifindex match
    // EGRESS: match lan client ip
    inet6_addr addr;
};

struct static_nat_mapping_value_v6 {
    // INGRESS: target LAN client prefix for NPTv6 dst replace, or suffix for self-ref match
    // EGRESS: unused
    inet6_addr addr;
    // INGRESS: unused
    // EGRESS: unused (CT uses pkt dst_addr as trigger)
    inet6_addr trigger_addr;
    // INGRESS: mapped port
    // EGRESS: unused
    __be16 port;
    // INGRESS: unused
    // EGRESS: unused
    __be16 trigger_port;
    u8 is_static;
    // EGRESS: used by create_ct6_egress when building static-backed CT
    // INGRESS: unused (ingress static CT always sets is_allow_reuse=1)
    u8 is_allow_reuse;
    u8 _pad[2];
    // unused in BPF
    u64 active_time;
};

struct nat4_mapping_value_v3 {
    u64 state_ref;
    __be32 addr;
    __be32 trigger_addr;
    __be16 port;
    __be16 trigger_port;
    u16 generation;
    u8 is_static;
    u8 is_allow_reuse;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct static_nat_mapping_key_v6);
    __type(value, struct static_nat_mapping_value_v6);
    __uint(max_entries, STATIC_NAT_MAPPING_CACHE_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat6_static_mappings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_mapping_key_v4);
    __type(value, struct nat4_mapping_value_v3);
    __uint(max_entries, NAT_MAPPING_CACHE_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nat4_st_map SEC(".maps");

#define NAT_CONN_ACTIVE 1
#define NAT_CONN_DELETE 2

struct nat_conn_metric_event {
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
    u32 cpu_id;
    u32 ifindex;
    u8 status;
    u8 gress;
} __nat_conn_metric_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} nat_conn_metric_events SEC(".maps");

#endif /* __LD_NAT_STATIC_H__ */
