#ifndef __LD_TC_WAN_EXIT_MAPS_H_
#define __LD_TC_WAN_EXIT_MAPS_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

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

#endif /* __LD_TC_WAN_EXIT_MAPS_H_ */
