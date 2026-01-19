#ifndef LD_MARK_H
#define LD_MARK_H
#include <bpf/bpf_helpers.h>
#include "vmlinux_wrapper.h"

#define FLOW_KEEP_GOING 0
#define FLOW_DIRECT 1
#define FLOW_DROP 2
#define FLOW_REDIRECT 3
#define FLOW_ALLOW_REUSE 4

#define FLOW_FROM_UNKNOW 0
#define FLOW_FROM_HOST 1
#define FLOW_FROM_LAN 2
#define FLOW_FROM_WAN 4

#define FLOW_SOURCE_MASK 0xFF000000
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

// 替换 FLOW_SOURCE_MASK 对应的 24~31 位
static __always_inline u32 replace_flow_source(u32 original, u8 new_source) {
    original &= ~FLOW_SOURCE_MASK;               // 清除原来的 Source 部分
    original |= ((u32)new_source & 0xFF) << 24;  // 设置新的 Source 部分
    return original;
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

static __always_inline u8 get_flow_source(u32 original) {
    return (original & FLOW_SOURCE_MASK) >> 24;
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

#endif /* LD_MARK_H */
