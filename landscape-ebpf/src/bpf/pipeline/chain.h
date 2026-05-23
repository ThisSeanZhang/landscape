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
 *   LAN chain :  root → fw → mss → lan_chain_exit
 *     (fallback: xdp_pipe_exits_lan)
 *   WAN chain :  root → fw → mss → wan_route
 *     (fallback: xdp_pipe_exits_wan)
 *   Stop mss:  root → fw → exit  (fw.next_stage[0] ← exit_fd)
 *
 * Tailcall pattern (BPF side):
 *   bpf_tail_call(ctx, &next_stage, 0);
 *   bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);  // or &xdp_pipe_exits_wan
 *   return XDP_PASS;
 *
 * Each chain direction has its own fallback PROG_ARRAY:
 *   xdp_pipe_exits_lan  — simple forward (bpf_redirect to target_ifindex)
 *   xdp_pipe_exits_wan  — full routing (bpf_redirect / bpf_redirect_neigh)
 *
 * Generic chain nodes (mss, nat, fw) provide two SEC("xdp")
 * entry points (_lan / _wan) that tailcall into the appropriate exit
 * map, so a single skel can serve both directions.
 *
 * Meta:
 *   root initializes meta.mark.  Each node may read and modify meta
 *   before tailcalling the next.  Use xdp_get_meta() / xdp_set_meta()
 *   from pipeline/pipeline.h.
 */

#endif /* __LD_CHAIN_H_ */
