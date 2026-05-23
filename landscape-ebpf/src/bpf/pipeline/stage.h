#ifndef __LD_STAGE_H_
#define __LD_STAGE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/*
 * Shared next_stage PROG_ARRAY for intermediate chain nodes
 * (mss, fw, nat, ...).  Every node that includes stage.h gets its
 * own `next_stage` map instance.
 *
 * max_entries = 2 so services exposing _lan / _wan entry points can
 * use separate slots for each direction:
 *   XDP_STAGE_NEXT_LAN (0) → LAN chain exit
 *   XDP_STAGE_NEXT_WAN (1) → WAN chain exit
 *
 * Chain roots are independent programs that declare their own
 * `root_next_stage` (max_entries=1, no stage.h dependency).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} next_stage SEC(".maps");

#define XDP_STAGE_NEXT_LAN 0
#define XDP_STAGE_NEXT_WAN 1

/*
 * Chain node pattern
 *
 *   Root (independent):     declares root_next_stage (max_entries=1)
 *     └─ root → root_next_stage[0] → first intermediate node
 *   Intermediate (stage.h): declares next_stage (max_entries=2)
 *     └─ stage → next_stage[LAN|WAN] → next hop / exit
 *
 * Chain link operation (Rust side):
 *   When a service starts, its program fd is inserted into the
 *   predecessor's next-hop map.  When a service stops, the
 *   predecessor's map is updated to point to the successor,
 *   then the stopped service's skel is dropped.
 *
 *   LAN chain :  root → root_next_stage[0]=mss_lan_fd
 *                mss → next_stage[LAN]=lan_chain_exit_fd
 *     (fallback: xdp_pipe_exits_lan)
 *   WAN chain :  root → root_next_stage[0]=mss_wan_fd
 *                mss → next_stage[WAN]=wan_route_fd
 *     (fallback: xdp_pipe_exits_wan)
 *   Stop mss:  root.root_next_stage[0] ← exit_fd
 *
 * Tailcall pattern (BPF side):
 *   // root:                           // intermediate:
 *   bpf_tail_call(ctx, &root_next_stage, 0);
 *   bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);  // or WAN
 *   bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);
 *   return XDP_PASS;
 *
 * Each chain direction has its own fallback PROG_ARRAY:
 *   xdp_pipe_exits_lan  — simple forward (bpf_redirect to target_ifindex)
 *   xdp_pipe_exits_wan  — full routing (bpf_redirect / bpf_redirect_neigh)
 *
 * Meta:
 *   root initializes meta.mark.  Each node may read and modify meta
 *   before tailcalling the next.  Use xdp_get_meta() / xdp_set_meta()
 *   from pipeline/pipeline.h.
 */

#endif /* __LD_STAGE_H_ */
