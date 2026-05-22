#ifndef __LD_CHAIN_H_
#define __LD_CHAIN_H_

/*
 * Chain node pattern
 *
 * Each intermediate chain node (fw / mss / nat) is a standalone XDP
 * program.  Every node declares its own PROG_ARRAY named `next_stage`
 * with `max_entries = 1`.  The array holds exactly one program fd —
 * the next hop in the chain.
 *
 * Chain link operation (Rust side):
 *   When a service starts, its program fd is inserted into the
 *   predecessor's `next_stage[0]`.  When a service stops, the
 *   predecessor's `next_stage[0]` is updated to point to the
 *   successor, then the stopped service's skel is dropped.
 *
 *   Example:  root → fw → mss → wan_route
 *   Stop mss: root → fw → wan_route  (fw.next_stage[0] ← wan_route_fd)
 *
 * Tailcall pattern (BPF side):
 *   bpf_tail_call(ctx, &next_stage, 0);
 *   bpf_tail_call(ctx, &xdp_pipe_exits, XDP_PIPE_EXIT_WAN_ROUTE);
 *   return XDP_PASS;
 *
 * The global xdp_pipe_exits acts as built-in fallback — when any
 * node's next_stage is empty, the packet is forwarded to wan_route
 * automatically.  wan_route itself does NOT declare next_stage; it
 * ends the chain with bpf_redirect().
 *
 * Meta:
 *   root initializes meta.mark.  Each node may read and modify meta
 *   before tailcalling the next.  Use xdp_get_meta() / xdp_set_meta()
 *   from pipeline/pipeline.h.
 */

#endif /* __LD_CHAIN_H_ */
