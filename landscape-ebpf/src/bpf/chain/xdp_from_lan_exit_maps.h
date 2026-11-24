#ifndef __LD_XDP_FROM_LAN_EXIT_MAPS_H_
#define __LD_XDP_FROM_LAN_EXIT_MAPS_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* Per-WAN chain from-LAN exit slot (unpinned; owned by the WAN link). */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_from_lan_exit_map SEC(".maps");

#define XDP_FROM_LAN_CHAIN_EXIT(ctx) bpf_tail_call_static((ctx), &xdp_from_lan_exit_map, 0)

#endif /* __LD_XDP_FROM_LAN_EXIT_MAPS_H_ */
