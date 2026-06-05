#ifndef __LD_TC_STAGE_H_
#define __LD_TC_STAGE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "tc_cb.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_ingress_next_stage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_next_stage SEC(".maps");

#define TC_NEXT_SLOT 0

#define TC_CHAIN_WAN_INGRESS(skb) bpf_tail_call((skb), &wan_ingress_next_stage, TC_NEXT_SLOT)
#define TC_CHAIN_WAN_EGRESS(skb) bpf_tail_call((skb), &wan_egress_next_stage, TC_NEXT_SLOT)

/*
 *  ============================================================================
 *  Architecture Overview
 *  ============================================================================
 *
 *  There are two independent TC chains: WAN ingress and WAN egress.
 *  LAN ingress traffic is routed to WAN egress via bpf_redirect and
 *  processed by the WAN egress chain.
 *  Each chain is composed of FDs linked via single-slot PROG_ARRAY maps.
 *  The Rust side (tc_chain/manager.rs) wires each service's FD into the
 *  predecessor's next-stage slot.
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  WAN INGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_intro (tc_wan_intro)
 *      └─ dispatch by daddr/prefix64/session_id
 *           └─ tc_pipe_root_progs[dispatch_idx]
 *                └─ tc_wan_chain_ingress_root
 *                     ├─ skb->cb[TC_CHAIN_CB_L3_OFFSET] = current_l3_offset  (injected)
 *                     ├─ bpf_tail_call(skb, &wan_ingress_root_next_stage, 0)
 *                     │    └─ PPPoE
 *                     │         └─ TC_CHAIN_WAN_INGRESS(skb) → MSS
 *                     │              └─ TC_CHAIN_WAN_INGRESS(skb) → FW
 *                     │                   └─ TC_CHAIN_WAN_INGRESS(skb) → NAT
 *                     │                        └─ TC_CHAIN_WAN_INGRESS(skb) → (next stage)
 *                     │
 *                     └─ bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, 0)
 *                          └─ tc_exit_wan_ingress_redirect  (Route = Exit)
 *                               ├─ route_wan_ingress entry (broadcast → v4/v6 dispatch)
 *                               ├─ rt4_wan_ingress / rt6_wan_ingress logic
 *                               └─ lan_redirect_check_v4/v6 → bpf_redirect(LAN)
 *
 *    Each stage (PPPoE / MSS / FW / NAT) shares the same exit map:
 *      tc_pipe_exits_wan_ingress[0] = tc_exit_wan_ingress_redirect
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  WAN EGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_wan_egress_intro  (Route logic, three entry paths)
 *      ├─ CB_FORWARDED → bpf_tail_call(&tc_wan_egress_roots, skb->ifindex)  (forwarded)
 *      ├─ ingress_ifindex != 0 → TC_ACT_OK  (compat bypass)
 *      └─ ingress_ifindex == 0  (local outbound)
 *           ├─ route_wan_egress entry (broadcast → v4/v6 dispatch)
 *           ├─ rt4_wan_egress / rt6_wan_egress logic
 *           └─ pick_wan:
 *                ├─ same WAN → bpf_tail_call(&tc_wan_egress_roots, target)
 *                └─ cross WAN → sets FORWARDED + bpf_redirect(target, 0)
 *
 *    tc_wan_chain_egress_root (per-WAN-interface)
 *      ├─ bpf_tail_call(skb, &wan_egress_root_next_stage, 0)
 *      │    └─ MSS
 *      │         └─ TC_CHAIN_WAN_EGRESS(skb) → NAT
 *      │              └─ TC_CHAIN_WAN_EGRESS(skb) → FW
 *      │                   └─ TC_CHAIN_WAN_EGRESS(skb) → PPPoE
 *      │                        └─ TC_CHAIN_WAN_EGRESS(skb) → (next stage)
 *      │
 *      └─ bpf_tail_call(skb, &tc_pipe_exits_wan_egress, 0)
 *           └─ tc_exit_wan_egress_redirect → TC_ACT_OK
 *
 *    Each stage (MSS / NAT / FW / PPPoE) shares the same exit map:
 *      tc_pipe_exits_wan_egress[0] = tc_exit_wan_egress_redirect
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  LAN INGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_lan_ingress_intro  (Route logic, selects WAN or LAN)
 *      ├─ tc_lan_redirect → LAN (direct LAN redirect)
 *      └─ tc_pick_wan → sets FORWARDED + bpf_redirect(target_wan, 0)
 *
 *    ▸ packet arrives at the egress of the target WAN interface
 *
 *    tc_wan_egress_intro sees CB_FORWARDED → bpf_tail_call(&tc_wan_egress_roots, skb->ifindex)
 *      └─ tc_wan_chain_egress_root
 *           ├─ MSS → NAT → FW → PPPoE  (WAN egress chain)
 *           └─ tc_pipe_exits_wan_egress → tc_exit_wan_egress_redirect → TC_ACT_OK
 *
 *    LAN ingress no longer injects stages; all egress processing happens
 *    on the WAN egress side after the redirect.
 *
 *  ============================================================================
 *  Chain node pattern & Rust wiring
 *  ============================================================================
 *
 *  Chain roots are independent programs that declare their own
 *  `wan_ingress_root_next_stage` / `wan_egress_root_next_stage`
 *  maps (max_entries=1 each, no tc_stage.h dependency).
 *
 *  Intro → tc_wan_egress_roots[ifindex]    → tc_wan_chain_egress_root  (WAN egress)
 *  Stage → wan_ingress_next_stage[0]       → next WAN ingress stage
 *  Stage → wan_egress_next_stage[0]        → next WAN egress stage
 *
 *  Chain link operation (Rust side):
 *    When a service starts, its program fds are written into the
 *    predecessor's next-stage map slot.  When a service stops,
 *    the predecessor's slot is redirected to the successor,
 *    then the stopped service's skel is dropped.
 *
 *    Example — WAN ingress chain:  PPPoE → MSS → FW → NAT → Exit
 *      root -> wan_ingress_root_next_stage[0] = pppoe_ingress_fd
 *      pppoe.wan_ingress_next_stage[0] = mss_ingress_fd
 *      mss.  wan_ingress_next_stage[0] = firewall_ingress_fd
 *      fw.   wan_ingress_next_stage[0] = nat_ingress_fd
 *      nat.  wan_ingress_next_stage[0] = (empty; fallback to exit)
 *
 *    Example — WAN egress chain:  MSS → NAT → FW → PPPoE → Exit
 *      root -> wan_egress_root_next_stage[0] = mss_egress_fd
 *      mss.   wan_egress_next_stage[0] = nat_egress_fd
 *      nat.   wan_egress_next_stage[0] = firewall_egress_fd
 *      fw.    wan_egress_next_stage[0] = pppoe_egress_fd
 *      pppoe. wan_egress_next_stage[0] = (empty; fallback to exit)
 *
 *    Example — LAN ingress chain:  tc_lan_ingress_intro → bpf_redirect (bypass)
 *      intro → route → pick_wan → FORWARDED + bpf_redirect(target_wan, 0)
 *      (LAN ingress stages no longer injected; processing moved to WAN egress)
 *
 *  Tailcall pattern (BPF side):
 *
 *    // WAN ingress stage:
 *    SEC("tc/ingress")
 *    int tc_xxx_wan_ingress(struct __sk_buff *skb) {
 *        // ... stage-specific logic ...
 *        bpf_tail_call(skb, &wan_ingress_next_stage, TC_NEXT_SLOT);
 *        return TC_ACT_OK;
 *    }
 *
 *    // WAN egress stage:
 *    SEC("tc/egress")
 *    int tc_xxx_wan_egress(struct __sk_buff *skb) {
 *        // ... stage-specific logic ...
 *        bpf_tail_call(skb, &wan_egress_next_stage, TC_NEXT_SLOT);
 *        return TC_ACT_OK;
 *    }
 *
 *  Fallback exit maps (declared in pipeline/tc_wan_exit_maps.h):
 *    tc_pipe_exits_wan_ingress — WAN ingress exit
 *    tc_pipe_exits_wan_egress  — WAN egress exit
 *
 *  Multi-entry prog arrays (declared in tc_wan_egress_chain.bpf.c):
 *    tc_wan_egress_roots — per-WAN egress chain roots (SEC tc/egress)
 */

#endif /* __LD_TC_STAGE_H_ */
