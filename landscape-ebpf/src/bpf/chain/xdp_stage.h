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
 * use separate slots per chain (chain identity = the side the packet
 * was received FROM, not where it is going):
 *   XDP_FROM_LAN_SLOT (0) → next hop of the from-LAN chain
 *   XDP_FROM_WAN_SLOT (1) → next hop of the from-WAN chain
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

#define XDP_FROM_LAN_SLOT 0
#define XDP_FROM_WAN_SLOT 1

#define XDP_FROM_LAN_CHAIN_NEXT(ctx) bpf_tail_call_static((ctx), &next_stage, XDP_FROM_LAN_SLOT)
#define XDP_FROM_WAN_CHAIN_NEXT(ctx) bpf_tail_call_static((ctx), &next_stage, XDP_FROM_WAN_SLOT)

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
 *   from-LAN chain (pkts received on a LAN if):
 *     root → root_next_stage[0]=mss_lan_fd
 *     mss → next_stage[FROM_LAN]=lan_chain_exit_fd
 *     (fallback: xdp_pipe_exits_lan)
 *   from-WAN chain (pkts received on the WAN if):
 *     root → root_next_stage[0]=mss_wan_fd
 *     mss → next_stage[FROM_WAN]=wan_route_fd
 *     (fallback: xdp_pipe_exits_wan)
 *   Stop mss:  root.root_next_stage[0] ← exit_fd
 *
 * Tailcall pattern (BPF side):
 *   // root:                           // intermediate:
 *   bpf_tail_call_static(ctx, &root_next_stage, 0);
 *   XDP_FROM_LAN_CHAIN_NEXT(ctx);   // or XDP_FROM_WAN_CHAIN_NEXT
 *   XDP_FROM_LAN_CHAIN_EXIT(ctx);   // or XDP_FROM_WAN_CHAIN_EXIT
 *   return XDP_PASS;
 *
 * Each chain direction has its own fallback PROG_ARRAY:
 *   xdp_pipe_exits_lan  — simple forward (bpf_redirect to target_ifindex)
 *   xdp_pipe_exits_wan  — full routing (bpf_redirect / bpf_redirect_neigh)
 *
 * Meta:
 *   root initializes meta.mark.  Each node may read and modify meta
 *   before tailcalling the next.  Use xdp_get_meta() / xdp_set_meta()
 *   from chain/xdp_meta.h.
 */

#endif /* __LD_STAGE_H_ */
