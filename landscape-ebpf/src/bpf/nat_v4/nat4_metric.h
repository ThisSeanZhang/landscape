/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_NAT4_METRIC_H
#define LAND_NAT_NAT4_METRIC_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "nat_v4/tc_nat4_map.h"

#define NAPT_METRIC_ACTIVE 1U
#define NAPT_METRIC_DELETE 2U
#define NAPT_METRIC_IPV4 0U

struct napt_metric_event {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u64 create_time;
    __u64 time;
    __u64 ingress_bytes;
    __u64 ingress_packets;
    __u64 egress_bytes;
    __u64 egress_packets;
    __u8 l4_proto;
    __u8 l3_proto;
    __u8 flow_id;
    __u8 trace_id;
    __u32 cpu_id;
    __u32 ifindex;
    __u8 status;
    __u8 gress;
};

_Static_assert(sizeof(struct napt_metric_event) == 104, "metric event wire size");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} nat_metric_events SEC(".maps");

static __always_inline int napt_metric_try_report(const struct napt_ct_key *key,
                                                  const struct napt_ct_value *value, __u8 status) {
    struct napt_metric_event *event;

    event = bpf_ringbuf_reserve(&nat_metric_events, sizeof(*event), 0);
    if (!event) return -1;

    event->src_addr.in6_u.u6_addr32[0] = key->internal_addr;
    event->dst_addr.in6_u.u6_addr32[0] = key->remote_addr;
    event->src_port = key->internal_port;
    event->dst_port = key->remote_port;
    event->l4_proto = key->proto;
    event->l3_proto = NAPT_METRIC_IPV4;
    event->flow_id = value->flow_id;
    event->trace_id = 0;
    event->time = bpf_ktime_get_tai_ns();
    event->create_time = value->create_time;
    event->ingress_bytes = value->ingress_bytes;
    event->ingress_packets = value->ingress_packets;
    event->egress_bytes = value->egress_bytes;
    event->egress_packets = value->egress_packets;
    event->cpu_id = value->cpu_id;
    event->ifindex = value->ifindex;
    event->status = status;
    event->gress = value->gress;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline void napt_metric_accumulate(struct __sk_buff *skb, u8 gress,
                                                   struct napt_ct_value *value) {
    u64 bytes = skb->len;

    if (gress == NAPT_GRESS_WAN) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

#endif /* LAND_NAT_NAT4_METRIC_H */
