// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __LD_SKB_CTX_H__
#define __LD_SKB_CTX_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* Load skb data pointers via opaque asm (mirroring DEFINE_XDP_CTX_POINTER in
 * chain/xdp_meta.h and skb_mark in base/mark.h): prevents Clang from hoisting
 * `&skb->data` / `&skb->data_end` offsets into registers across adjacent
 * packet reads and tripping the verifier's "dereference of modified ctx ptr"
 * check.
 *
 * A fixed "i" offset is required: a runtime register offset would compile to
 * `*(u32 *)(skb + reg)` and trip the same verifier check. */
static __always_inline char *skb_data(const struct __sk_buff *skb) {
    char *ptr;
    __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"
                         : "=r"(ptr)
                         : "r"(skb), "i"(offsetof(struct __sk_buff, data)));
    return ptr;
}

static __always_inline char *skb_data_end(const struct __sk_buff *skb) {
    char *ptr;
    __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"
                         : "=r"(ptr)
                         : "r"(skb), "i"(offsetof(struct __sk_buff, data_end)));
    return ptr;
}

#endif /* __LD_SKB_CTX_H__ */
