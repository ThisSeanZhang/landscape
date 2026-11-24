#ifndef __LD_TC_FROM_WAN_EXIT_MAPS_H_
#define __LD_TC_FROM_WAN_EXIT_MAPS_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/tc_exit_slots.h"

/* Shared from-WAN exit slot (pinned by the route backbone). */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_exits_wan_ingress SEC(".maps");

#define TC_FROM_WAN_CHAIN_EXIT(skb)                                                                \
    bpf_tail_call_static((skb), &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT)

#endif /* __LD_TC_FROM_WAN_EXIT_MAPS_H_ */
