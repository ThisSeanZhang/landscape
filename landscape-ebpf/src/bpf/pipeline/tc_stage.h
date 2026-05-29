#ifndef __LD_TC_STAGE_H_
#define __LD_TC_STAGE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} lan_ingress_next_stage SEC(".maps");

#define TC_NEXT_SLOT 0

#define TC_CHAIN_WAN_INGRESS(skb) bpf_tail_call((skb), &wan_ingress_next_stage, TC_NEXT_SLOT)
#define TC_CHAIN_WAN_EGRESS(skb) bpf_tail_call((skb), &wan_egress_next_stage, TC_NEXT_SLOT)
#define TC_CHAIN_LAN_INGRESS(skb) bpf_tail_call((skb), &lan_ingress_next_stage, TC_NEXT_SLOT)

/*
 *  Chain node pattern (TC)
 *
 *  Chain roots are independent programs that declare their own
 *  `wan_ingress_root_next_stage` / `wan_egress_root_next_stage` /
 *  `lan_ingress_root_next_stage` maps (max_entries=1 each, no
 *  tc_stage.h dependency).
 *
 *  Root → ingress_root_next_stage[0]  → first stage
 *  Root → egress_root_next_stage[0]   → first stage
 *  Stage → wan_ingress_next_stage[0]  → next WAN ingress stage
 *  Stage → wan_egress_next_stage[0]   → next WAN egress stage
 *  Stage → lan_ingress_next_stage[0]  → next LAN ingress stage
 *
 *  Chain link operation (Rust side):
 *    When a service starts, its program fds are written into the
 *    predecessor's next-stage map slot.  When a service stops,
 *    the predecessor's slot is redirected to the successor,
 *    then the stopped service's skel is dropped.
 *
 *    Example — WAN ingress chain:  PPPoE → MSS → FW → NAT → Route
 *      root -> wan_ingress_root_next_stage[0] = pppoe_ingress_fd
 *      pppoe.wan_ingress_next_stage[0] = mss_ingress_fd
 *      mss.  wan_ingress_next_stage[0] = firewall_ingress_fd
 *      fw.   wan_ingress_next_stage[0] = nat_ingress_fd
 *      nat.  wan_ingress_next_stage[0] = route_ingress_fd
 *
 *    Example — WAN egress chain:  Route → MSS → NAT → FW → PPPoE
 *      root -> wan_egress_root_next_stage[0] = route_egress_fd
 *      route. wan_egress_next_stage[0] = mss_egress_fd
 *      mss.   wan_egress_next_stage[0] = nat_egress_fd
 *      nat.   wan_egress_next_stage[0] = firewall_egress_fd
 *      fw.    wan_egress_next_stage[0] = pppoe_egress_fd
 *
 *    Example — LAN ingress chain:  LAN Route only
 *      root -> lan_ingress_root_next_stage[0] = lan_route_ingress_fd
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
 *    // LAN ingress stage:
 *    SEC("tc/ingress")
 *    int tc_xxx_lan_ingress(struct __sk_buff *skb) {
 *        // ... stage-specific logic ...
 *        bpf_tail_call(skb, &lan_ingress_next_stage, TC_NEXT_SLOT);
 *        return TC_ACT_OK;
 *    }
 *
 *  Fallback exit maps (shared, from tc_pipe_seed.bpf.c):
 *    tc_pipe_exits_wan_ingress — WAN ingress exit
 *    tc_pipe_exits_wan_egress  — WAN egress exit
 *    tc_pipe_exits_lan_ingress — LAN ingress exit
 */

#endif /* __LD_TC_STAGE_H_ */
