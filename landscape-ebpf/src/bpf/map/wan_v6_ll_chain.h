#ifndef __LD_MAP_WAN_V6_LL_CHAIN_H__
#define __LD_MAP_WAN_V6_LL_CHAIN_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// IPv6CP link-local of an L3 (native PPPoE) WAN session -> chain id.
// Published by the wan link dataplane at session attach, removed by the
// session guard drop.  Read by the WAN egress classifier's broadcast
// branch: an L3 WAN has no raw multicast, so the session's v6 control
// plane (multicast / link-local dst, e.g. DHCPv6-PD renewals to
// ff02::1:2) must enter the chain for PPP encapsulation.  Keyed by
// address (the kernel sources this traffic from the iface's only
// link-local), not ifindex, so sessions on one iface stay distinct.
//
// MARK_DESIGN: when marks are redesigned, consult skb->mark (SO_MARK on
// the DHCPv6 socket -> flow -> wan slots) first; the src-lookup stays
// as the catch-all for kernel-originated control (MLD, NS).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct in6_addr);
    __type(value, u32);
    __uint(max_entries, 64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} wan_v6_ll_chain SEC(".maps");

#endif /* __LD_MAP_WAN_V6_LL_CHAIN_H__ */
