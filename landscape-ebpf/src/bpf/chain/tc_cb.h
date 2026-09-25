#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// `struct __sk_buff::cb` is a `__u32[5]` window into the skb control buffer,
// so each offset below addresses a full u32 slot.
//
// slot 0: set by pick_wan; read by tc_wan_egress_intro to enter chain
#define TC_CHAIN_CB_FORWARDED_OFFSET 0
// slot 1: set by tc_wan_chain_ingress_root; read by WAN ingress exit
#define TC_CHAIN_CB_L3_OFFSET 1
// slot 2: logical WAN chain selected for this packet
#define TC_CHAIN_CB_CHAIN_ID_OFFSET 2

// Helpers keep every read/write of the chain-id slot going through one
// place, and document that the value is a full u32 (chain ids are allocated
// in 1..=1023).
static __always_inline void tc_cb_set_chain_id(struct __sk_buff *skb, u32 chain_id) {
    skb->cb[TC_CHAIN_CB_CHAIN_ID_OFFSET] = chain_id;
}

static __always_inline u32 tc_cb_chain_id(const struct __sk_buff *skb) {
    return skb->cb[TC_CHAIN_CB_CHAIN_ID_OFFSET];
}

#endif /* __LD_TC_CB_H_ */
