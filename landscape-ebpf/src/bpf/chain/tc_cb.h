#ifndef __LD_TC_CB_H_
#define __LD_TC_CB_H_

#include <vmlinux.h>

// Family-indexed chain slots (see chain/tc_stage.h).  Defined here because
// the chain roots do not include tc_stage.h.
#define TC_SLOT_V4 0
#define TC_SLOT_V6 1

/*
 * skb->cb control block (5 x u32):
 *
 *   cb[0]  b0       forwarded (routing entered another chain)
 *   cb[1]  b0-b7    l3 offset (stamped by the chain root)
 *          b16-b31   chain id
 *
 * cb[2..4] are unused: every stage re-reads the packet instead of caching a
 * parse result in skb->cb.
 */

static __always_inline bool tc_cb_forwarded(const struct __sk_buff *skb) { return skb->cb[0] & 1; }

static __always_inline void tc_cb_mark_forwarded(struct __sk_buff *skb, u32 chain_id) {
    u32 cb1 = skb->cb[1];
    skb->cb[0] = 1;
    skb->cb[1] = (cb1 & 0xFFFFu) | (chain_id << 16);
}

static __always_inline u16 tc_cb_chain(const struct __sk_buff *skb) { return skb->cb[1] >> 16; }

static __always_inline u8 tc_cb_l3_offset(const struct __sk_buff *skb) { return skb->cb[1] & 0xFF; }

static __always_inline void tc_cb_ingress_stamp(struct __sk_buff *skb, u32 l3_offset,
                                                u32 chain_id) {
    skb->cb[1] = (chain_id << 16) | (l3_offset & 0xFF);
}

#endif /* __LD_TC_CB_H_ */
