#ifndef __LD_MARK_H__
#define __LD_MARK_H__
#include <bpf/bpf_helpers.h>
#include <vmlinux.h>

#define FLOW_KEEP_GOING 0
#define FLOW_DIRECT 1
#define FLOW_DROP 2
#define FLOW_REDIRECT 3
#define FLOW_ALLOW_REUSE 4

// bits 24-31: mark layout-type tag (Normal layout = 0, HostDirect layout = 1)
// bits 16-23: trace_mark (reserved for observability, carried by both
//             layouts, always 0 for now)
#define MARK_TYPE_NORMAL 0
#define MARK_TYPE_HOST_DIRECT 1

#define MARK_TYPE_MASK 0xFF000000
#define FLOW_ACTION_MASK 0x00007F00
#define FLOW_ALLOW_REUSE_PORT_MASK 0x00008000
#define FLOW_ID_MASK 0x000000FF

// 替换 FLOW_ID_MASK 对应的 0~7 位
static __always_inline u32 replace_flow_id(u32 original, u8 new_id) {
    original &= ~FLOW_ID_MASK;         // 清除原来的 ID 部分
    original |= ((u32)new_id & 0xFF);  // 设置新的 ID 部分
    return original;
}

// 替换 FLOW_ACTION_MASK 对应的 8~14 位
static __always_inline u32 replace_flow_action(u32 original, u8 new_action) {
    original &= ~FLOW_ACTION_MASK;              // 清除原来的 Action 部分
    original |= ((u32)new_action & 0x7F) << 8;  // 只取低 7 bit，写入 8~14 位
    return original;
}

// 替换 FLOW_ALLOW_REUSE_PORT_MASK 对应的第 15 位
static __always_inline u32 set_flow_allow_reuse_port(u32 original, bool allow) {
    original &= ~FLOW_ALLOW_REUSE_PORT_MASK;  // 清除原来的标志位
    if (allow) {
        original |= FLOW_ALLOW_REUSE_PORT_MASK;  // 设置为 1
    }
    return original;
}

/* Read/write skb->mark through opaque asm (same idea as the ctx pointer
 * accessors in chain/xdp_meta.h): every call is exactly one load / one store
 * at the call site, so the compiler can neither reuse a stale mark value nor
 * elide or move a store.  Unlike a positional barrier_var(), the guarantee
 * travels with each use site. */
static __always_inline u32 skb_mark(const struct __sk_buff *skb) {
    u32 v;
    __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"
                         : "=r"(v)
                         : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, mark)));
    return v;
}

static __always_inline void skb_set_mark(struct __sk_buff *skb, u32 v) {
    __asm__ __volatile__("*(u32 *)(%0 + %2) = %1"
                         :
                         : "r"(skb), "r"(v), "i"(__builtin_offsetof(struct __sk_buff, mark)));
}

static __always_inline u8 get_flow_id(u32 original) { return (original & FLOW_ID_MASK); }

// 获取 action
static __always_inline u8 get_flow_action(u32 original) {
    return (original & FLOW_ACTION_MASK) >> 8;  // 返回 0–127
}

// 获取 reuse port 标志
static __always_inline bool get_flow_allow_reuse_port(u32 original) {
    return (original & FLOW_ALLOW_REUSE_PORT_MASK) != 0;
}

// Get the mark layout type (bits 24-31)
static __always_inline u8 get_mark_type(u32 original) { return (original & MARK_TYPE_MASK) >> 24; }

// Whether the mark uses the HostDirect layout
static __always_inline bool is_host_direct(u32 original) {
    return get_mark_type(original) == MARK_TYPE_HOST_DIRECT;
}

// Whether the mark does NOT use the HostDirect layout
static __always_inline bool not_host_direct(u32 original) { return !is_host_direct(original); }

// chain_id of the HostDirect layout (bits 0-15)
static __always_inline u16 get_host_direct_chain_id(u32 original) {
    return (u16)(original & 0xFFFF);
}

// INGRESS MARK
#define INGRESS_NO_MARK 0
#define INGRESS_STATIC_MARK 1

#define INGRESS_CACHE_MASK 0x000000FF

// 替换 INGRESS_CACHE_MASK 对应的 0~7 位
static __always_inline u32 replace_cache_mask(u32 original, u8 new_mark) {
    original &= ~INGRESS_CACHE_MASK;
    original |= ((u32)new_mark & 0xFF);
    return original;
}

static __always_inline u8 get_cache_mask(u32 original) { return (original & INGRESS_CACHE_MASK); }

#endif /* __LD_MARK_H__ */
