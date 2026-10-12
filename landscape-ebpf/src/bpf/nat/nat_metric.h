#ifndef __LD_NAT_METRIC_H__
#define __LD_NAT_METRIC_H__

#include <bpf/bpf_helpers.h>
#include <vmlinux.h>
#include "nat/nat_common.h"

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
} nat_metric_events SEC(".maps");

#endif /* __LD_NAT_METRIC_H__ */
