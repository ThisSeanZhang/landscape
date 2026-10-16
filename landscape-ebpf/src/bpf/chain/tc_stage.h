#ifndef __LD_TC_STAGE_H_
#define __LD_TC_STAGE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/tc_cb.h"

/*
 * Family-indexed chain slots (TC_SLOT_V4/TC_SLOT_V6, defined in tc_cb.h).
 * Each stage provides one program per family; the family programs hardcode
 * their own slot constant so every hop stays a bpf_tail_call_static with a
 * compile-time key (x86-64 JIT direct jump).  Roots fork once on the L3
 * protocol; non-IP packets take no tail call and fall through to the exit.
 */

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_ingress_next_stage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_next_stage SEC(".maps");

#define TC_FROM_WAN_CHAIN_NEXT(skb, slot) bpf_tail_call_static((skb), &wan_ingress_next_stage, slot)
#define TC_FROM_LAN_CHAIN_NEXT(skb, slot) bpf_tail_call_static((skb), &wan_egress_next_stage, slot)

/*
 *  ============================================================================
 *  Architecture Overview
 *  ============================================================================
 *
 *  There are two independent TC chains: WAN ingress and WAN egress.
 *  LAN ingress traffic is routed to WAN egress via bpf_redirect and
 *  processed by the WAN egress chain.
 *  Each chain is composed of FDs linked via single-slot PROG_ARRAY maps.
 *  The Rust side (chain/tc_manager.rs) wires each service's FD into the
 *  predecessor's next-stage slot.
 *
 *  BPF source files (src/bpf/):
 *    tc_wan_ingress_intro.bpf.c — WAN ingress classifier (tc_wan_ingress_intro)
 *    tc_wan_ingress_root.bpf.c  — per-WAN ingress chain root (family fork)
 *    tc_wan_egress_root.bpf.c   — per-WAN egress chain root (family fork)
 *    tc_wan_egress_route.bpf.c  — WAN egress route + classifier
 *
 *  Every stage object carries a v4 and a v6 entry program for each chain
 *  direction; each entry tails into the family slot it belongs to, so the
 *  two families traverse independent program lineups within one chain.
 *  PPPoE encap (native mode) is an egress-only per-link terminal stage
 *  with the same family-dual entries, its session template baked into
 *  rodata per link (see PppoeHandle::attach_tc_pppoe).
 *
 *  Both ingress and egress roots are always instantiated (TcChainManager::
 *  ensure_roots), with tc_wan_egress_route attached to TC egress for
 *  local-outbound traffic and tc_wan_ingress_intro for WAN ingress.
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  WAN INGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_wan_ingress_intro
 *      └─ dispatch by daddr/prefix64/session_id
 *           └─ tc_pipe_root_progs[dispatch_idx]
 *                └─ tc_wan_ingress_root
 *                     ├─ tc_cb_ingress_stamp(skb, l3_offset, chain_id)
 *                     ├─ L3 protocol fork: slot0 (v4) / slot1 (v6)
 *                     │    └─ MSS_{v4,v6}
 *                     │         └─ TC_FROM_WAN_CHAIN_NEXT(skb, slot) → FW_{v4,v6}
 *                     │              └─ TC_FROM_WAN_CHAIN_NEXT(skb, slot) → NAT_{v4,v6}
 *                     │                   └─ TC_FROM_WAN_CHAIN_NEXT(skb, slot) → (next stage)
 *                     │
 *                     └─ bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, 0)
 *                          └─ tc_wan_ingress_route  (Route = Exit)
 *                               ├─ route_wan_ingress entry (broadcast → v4/v6 dispatch)
 *                               ├─ rt4_wan_ingress / rt6_wan_ingress logic
 *                               └─ tc_route4/6_lan_redirect_check_in_wan → bpf_redirect(LAN)
 *
 *    Each stage (MSS / FW / NAT) shares the same exit map:
 *      tc_pipe_exits_wan_ingress[0] = tc_wan_ingress_route
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  WAN EGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_wan_egress_route  (Route logic, three entry paths)
 *      ├─ CB_FORWARDED → bpf_tail_call(&tc_wan_egress_roots,
 *      │    tc_cb_chain(skb))  (forwarded; routed by a
 *      │    landscape pick_wan earlier, its target chain id rides in cb)
 *      ├─ ingress_ifindex != 0 → DIRECT_{V4,V6}_SLOT of ls_wan_e_tails
 *      │    (LAN-originated forwarded handoff: the LAN side already ran
 *      │    its flow verdict, so the direct workers skip the verdict and
 *      │    hand the preserved flow id to pick_wan — flow-0 default
 *      │    slots when the mark carries none)
 *      └─ ingress_ifindex == 0  (local outbound)
 *           ├─ route_wan_egress entry (broadcast → v4/v6 dispatch)
 *           │    ├─ HostDirect mark (SO_MARK, chain id in bits 0-15):
 *           │    │    host control plane → chain root directly; the
 *           │    │    policy stages self-skip on that mark
 *           │    └─ broadcast/multicast MAC: pass-through
 *           ├─ rt4_wan_egress / rt6_wan_egress logic
 *           └─ tc_route4/6_pick_wan_in_wan_egress:
 *                ├─ same WAN → bpf_tail_call(&tc_wan_egress_roots, target chain)
 *                └─ cross WAN → sets FORWARDED + chain id in cb + bpf_redirect(target, 0)
 *
 *    tc_wan_egress_root (per-WAN-interface, in tc_wan_egress_root.bpf.c)
 *      ├─ L3 protocol fork: slot0 (v4) / slot1 (v6)
 *      │    └─ MSS_{v4,v6}
 *      │         └─ TC_FROM_LAN_CHAIN_NEXT(skb, slot) → FW_{v4,v6}
 *      │              └─ TC_FROM_LAN_CHAIN_NEXT(skb, slot) → NAT_{v4,v6}
 *      │                   └─ TC_FROM_LAN_CHAIN_NEXT(skb, slot) → PPPoE_{v4,v6}
 *      │                        └─ TC_FROM_LAN_CHAIN_NEXT(skb, slot) → (next stage)
 *      │
 *      └─ bpf_tail_call(skb, &tc_pipe_exits_wan_egress, 0)
 *           └─ tc_wan_egress_exit_redirect → TC_ACT_OK
 *
 *    Each stage (MSS / FW / NAT / PPPoE) shares the same exit map:
 *      tc_pipe_exits_wan_egress[0] = tc_wan_egress_exit_redirect
 *
 *  ─────────────────────────────────────────────────────────────────────────
 *  LAN INGRESS CHAIN
 *  ─────────────────────────────────────────────────────────────────────────
 *
 *    tc_lan_ingress_route  (Route logic, selects WAN or LAN)
 *      ├─ tc_route4/6_lan_redirect_check_in_lan → LAN (direct LAN redirect)
 *      └─ tc_route4/6_pick_wan_in_lan → sets FORWARDED + bpf_redirect(target_wan, 0)
 *
 *    ▸ packet arrives at the egress of the target WAN interface
 *
 *    tc_wan_egress_route sees CB_FORWARDED → bpf_tail_call(&tc_wan_egress_roots,
 *                                                          cb chain id)
 *      └─ tc_wan_egress_root
 *           ├─ MSS → FW → NAT  (WAN egress chain)
 *           └─ tc_pipe_exits_wan_egress → tc_wan_egress_exit_redirect → TC_ACT_OK
 *
 *    LAN ingress no longer injects stages; all egress processing happens
 *    on the WAN egress side after the redirect.
 *
 *  ============================================================================
 *  Chain node pattern & Rust wiring
 *  ============================================================================
 *
 *  Chain roots are independent programs that declare their own
 *  `wan_ingress_root_next_stage` (in tc_wan_ingress_root.bpf.c)
 *  and `wan_egress_root_next_stage` (in tc_wan_egress_root.bpf.c)
 *  maps (family-indexed, max_entries=2 each, no tc_stage.h dependency).
 *
 *  Intro → tc_wan_egress_roots[chain]    → tc_wan_egress_root  (WAN egress)
 *  Stage → wan_ingress_next_stage[slot]    → next WAN ingress stage (slot = v4/v6)
 *  Stage → wan_egress_next_stage[slot]     → next WAN egress stage (slot = v4/v6)
 *
 * Chain link operation (Rust side):
 *    When a service starts, its per-family program fds are written into the
 *    predecessor's next-stage slots (slot 0 = v4, slot 1 = v6).  When a
 *    service stops, the predecessor's slots are redirected to the successor,
 *    then the stopped service's skel is dropped.
 *
 *    Example — WAN ingress chain:  MSS → FW → NAT → Exit
 *      root -> wan_ingress_root_next_stage[TC_SLOT_V4] = mss_ingress_v4_fd
 *      root -> wan_ingress_root_next_stage[TC_SLOT_V6] = mss_ingress_v6_fd
 *      mss.  wan_ingress_next_stage[TC_SLOT_V4] = firewall_ingress_v4_fd
 *      ...
 *      nat.  wan_ingress_next_stage[*] = (empty; fallback to exit)
 *
 *    Example — WAN egress chain:  MSS → FW → NAT → [PPPoE] → Exit
 *      root -> wan_egress_root_next_stage[TC_SLOT_V4] = mss_egress_v4_fd
 *      root -> wan_egress_root_next_stage[TC_SLOT_V6] = mss_egress_v6_fd
 *      mss.  wan_egress_next_stage[TC_SLOT_V4] = firewall_egress_v4_fd
 *      mss.  wan_egress_next_stage[TC_SLOT_V6] = firewall_egress_v6_fd
 *      ... (each stage links both family slots to the successor)
 *      nat.  wan_egress_next_stage[*] = pppoe_egress_{v4,v6}_fd   (native PPPoE)
 *      pppoe.wan_egress_next_stage[*] = (empty; fallback to exit)
 *
 *    PPPoE (native mode) is egress-only and per-link: each link injects
 *    its own terminal stage with its session template in rodata
 *    (see PppoeHandle::attach_tc_pppoe).  Rust-side it only registers
 *    from-LAN (egress) rows: the from-WAN stage enum has no Pppoe
 *    variant, so it can never join the WAN ingress chain.
 *
 *    Example — LAN ingress chain:  tc_lan_ingress_route → bpf_redirect (bypass)
 *      intro → route → pick_wan → FORWARDED + bpf_redirect(target_wan, 0)
 *      (LAN ingress stages no longer injected; processing moved to WAN egress)
 *
 *  Tailcall pattern (BPF side):
 *
 *    // WAN ingress v4 stage entry (v6 twin passes TC_SLOT_V6):
 *    SEC("tc/ingress")
 *    int tc_xxx_wan_ingress_v4(struct __sk_buff *skb) {
 *        // ... v4-only stage logic ...
 *        bpf_tail_call(skb, &wan_ingress_next_stage, TC_SLOT_V4);
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
 *  Fallback exit maps (declared in chain/tc_wan_exit_maps.h):
 *    tc_pipe_exits_wan_ingress — WAN ingress exit
 *    tc_pipe_exits_wan_egress  — WAN egress exit
 *
 *  Multi-entry prog arrays (declared in tc_wan_egress_route.bpf.c):
 *    tc_wan_egress_roots — per-WAN-link egress chain roots, keyed by the
 *    link's chain id (SEC tc/egress)
 */

#endif /* __LD_TC_STAGE_H_ */
