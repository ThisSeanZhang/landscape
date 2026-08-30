#ifndef __LD_IP_NEIGH6_EVENT_H__
#define __LD_IP_NEIGH6_EVENT_H__

#include <bpf/bpf_helpers.h>
#include <vmlinux.h>

// Emitted by tc_lan_dao on a newly learned DAD NS target, and again when a
// different host re-claims an address whose binding is itself DAD-learned
// (userspace re-verifies liveness). Ringbuf wire layout; the explicit pad
// keeps both sides at the same size without relying on implicit tail padding.
struct ip6_dao_event {
    u32 ifindex;
    u8 ip[16];
    u8 mac[6];
    u8 __pad[6];
} __ip6_dao_event;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ip6_dao_events SEC(".maps");

#endif /* __LD_IP_NEIGH6_EVENT_H__ */
