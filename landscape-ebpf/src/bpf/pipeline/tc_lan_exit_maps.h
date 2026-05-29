#ifndef __LD_TC_LAN_EXIT_MAPS_H_
#define __LD_TC_LAN_EXIT_MAPS_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_lan_ingress_roots SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_exits_lan_ingress SEC(".maps");

#endif /* __LD_TC_LAN_EXIT_MAPS_H_ */
