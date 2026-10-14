#ifndef __LD_STAGE_H_
#define __LD_STAGE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/*
 * Shared next_stage PROG_ARRAY for intermediate chain nodes
 * (mss, fw, nat, ...).  Every node that includes stage.h gets its
 * own `next_stage` map instance.
 *
 * max_entries = 4: one slot per (chain direction x IP family).
 * Chain identity = the side the packet was received FROM, not where
 * it is going; family slots are chosen by the chain roots, which fork
 * once on the L3 protocol, so every hop stays a bpf_tail_call_static
 * with a compile-time key:
 *   XDP_FROM_LAN_SLOT_V4 (0) -> next hop of the from-LAN v4 chain
 *   XDP_FROM_LAN_SLOT_V6 (1) -> next hop of the from-LAN v6 chain
 *   XDP_FROM_WAN_SLOT_V4 (2) -> next hop of the from-WAN v4 chain
 *   XDP_FROM_WAN_SLOT_V6 (3) -> next hop of the from-WAN v6 chain
 *
 * Chain roots are independent programs that declare their own
 * `root_next_stage` (max_entries=2, family-indexed; the root slot
 * constants live in chain/xdp_cb.h, which roots include instead of
 * this header).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} next_stage SEC(".maps");

#define XDP_FROM_LAN_SLOT_V4 0
#define XDP_FROM_LAN_SLOT_V6 1
#define XDP_FROM_WAN_SLOT_V4 2
#define XDP_FROM_WAN_SLOT_V6 3

#define XDP_FROM_LAN_CHAIN_NEXT_V4(ctx)                                                            \
    bpf_tail_call_static((ctx), &next_stage, XDP_FROM_LAN_SLOT_V4)
#define XDP_FROM_LAN_CHAIN_NEXT_V6(ctx)                                                            \
    bpf_tail_call_static((ctx), &next_stage, XDP_FROM_LAN_SLOT_V6)
#define XDP_FROM_WAN_CHAIN_NEXT_V4(ctx)                                                            \
    bpf_tail_call_static((ctx), &next_stage, XDP_FROM_WAN_SLOT_V4)
#define XDP_FROM_WAN_CHAIN_NEXT_V6(ctx)                                                            \
    bpf_tail_call_static((ctx), &next_stage, XDP_FROM_WAN_SLOT_V6)

/*
 * Chain node pattern
 *
 *   Root (independent):     declares root_next_stage (max_entries=2,
 *                           family-indexed via chain/xdp_cb.h)
 *     └─ root → root_next_stage[V4|V6] → first intermediate node
 *   Intermediate (stage.h): declares next_stage (max_entries=4)
 *     └─ stage → next_stage[DIR_SLOT_V4|V6] → next hop / exit
 *
 * Chain link operation (Rust side):
 *   When a service starts, its per-family program fds are inserted
 *   into the predecessor's next-hop slots (slot = direction x
 *   family).  When a service stops, the predecessor's slots are
 *   redirected to the successor, then the stopped service's skel is
 *   dropped.
 *
 *   from-LAN chain (pkts received on a LAN if):
 *     root → root_next_stage[V4]=mss_lan_v4_fd   (and [V6]=mss_lan_v6_fd)
 *     mss → next_stage[FROM_LAN_V4]=fw_lan_v4_fd (and _V6 twin)
 *     (fallback: xdp_pipe_exits_lan)
 *   from-WAN chain (pkts received on the WAN if):
 *     root → root_next_stage[V4]=mss_wan_v4_fd   (and [V6]=mss_wan_v6_fd)
 *     mss → next_stage[FROM_WAN_V4]=fw_wan_v4_fd (and _V6 twin)
 *     (fallback: xdp_pipe_exits_wan)
 *   Stop mss:  root.root_next_stage[V4|V6] ← exit path
 *
 * Tailcall pattern (BPF side):
 *   // root (family fork):              // intermediate (v4 twin shown):
 *   switch (xdp_classify_l3(ctx)) {     XDP_FROM_LAN_CHAIN_NEXT_V4(ctx);
 *   case XDP_L3_V6:                     XDP_FROM_LAN_CHAIN_EXIT(ctx);
 *       tail(root_next_stage, V6);      return XDP_PASS;
 *       break;
 *   case XDP_L3_V4:
 *       tail(root_next_stage, V4);
 *       break;
 *   default:
 *       break;  // non-IP: no tail call, fall through to the exit
 *   }
 *
 * Each chain direction has its own fallback PROG_ARRAY (single-slot,
 * family-agnostic):
 *   xdp_pipe_exits_lan  — simple forward (bpf_redirect to target_ifindex)
 *   xdp_pipe_exits_wan  — full routing (bpf_redirect / bpf_redirect_neigh)
 *
 * Meta:
 *   root initializes meta.mark.  Each node may read and modify meta
 *   before tailcalling the next.  Use xdp_get_meta() / xdp_set_meta()
 *   from chain/xdp_meta.h.
 */

#endif /* __LD_STAGE_H_ */
