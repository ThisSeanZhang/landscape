#ifndef __LD_XDP_LAN_MAPS_H_
#define __LD_XDP_LAN_MAPS_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/xdp_pipe_def.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, XDP_PIPE_MAX_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_lan_pipe_root_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_pipe_exits_lan SEC(".maps");

#define XDP_FROM_LAN_CHAIN_EXIT(ctx) bpf_tail_call_static((ctx), &xdp_pipe_exits_lan, 0)

#endif /* __LD_XDP_LAN_MAPS_H_ */
