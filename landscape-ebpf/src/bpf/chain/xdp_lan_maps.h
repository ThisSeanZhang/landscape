#ifndef __LD_XDP_LAN_MAPS_H_
#define __LD_XDP_LAN_MAPS_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/xdp_pipe_def.h"

/* From-LAN direction chain roots of WAN links, keyed by the owning link's
 * chain id (LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX, slot 0 unused).  Entered
 * via bpf_tail_call from xdp_lan_route once a route slot/cache target
 * resolves to a WAN link; the instances are xdp_lan_root programs stamped
 * with their chain id.  LAN interfaces register nothing here: they attach
 * xdp_lan_route directly and reach the WAN link chains through this array. */
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
