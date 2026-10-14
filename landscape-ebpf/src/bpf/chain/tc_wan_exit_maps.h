#ifndef __LD_TC_WAN_EXIT_MAPS_H_
#define __LD_TC_WAN_EXIT_MAPS_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// Single PROG_ARRAY slot used by TC chain roots/stages for their next hop.
#define TC_NEXT_SLOT 0

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_exits_wan_ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_exits_wan_egress SEC(".maps");

#define TC_FROM_WAN_CHAIN_EXIT(skb)                                                                \
    bpf_tail_call_static((skb), &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT)
#define TC_FROM_LAN_CHAIN_EXIT(skb)                                                                \
    bpf_tail_call_static((skb), &tc_pipe_exits_wan_egress, TC_NEXT_SLOT)

#endif /* __LD_TC_WAN_EXIT_MAPS_H_ */
