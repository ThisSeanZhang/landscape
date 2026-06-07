#ifndef __LD_XDP_WAN_MAPS_H_
#define __LD_XDP_WAN_MAPS_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define XDP_PIPE_MAX_ENTRIES 1024

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, XDP_PIPE_MAX_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_pipe_root_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_pipe_exits_wan SEC(".maps");

#endif /* __LD_XDP_WAN_MAPS_H_ */
