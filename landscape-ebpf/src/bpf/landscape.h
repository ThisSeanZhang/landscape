#ifndef __LD_LANDSCAPE_H__
#define __LD_LANDSCAPE_H__
#include "vmlinux.h"
#include "landscape_log.h"

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3

#define BPF_LOOP_RET_CONTINUE 0
#define BPF_LOOP_RET_BREAK 1

#define ETH_P_8021Q 0x8100
#define LAND_REDIRECT_NETNS_VLAN_ID 0x1d

#define ETH_IPV4 bpf_htons(0x0800) /* ETH IPV4 packet */
#define ETH_IPV6 bpf_htons(0x86DD) /* ETH IPv6 packet */
#define ETH_ARP bpf_htons(0x0806)  /* ETH ARP packet */

#define AF_INET 2
#define AF_INET6 10

// L4 proto number
#define IPPROTO_ICMPV6 58

#define OK_MARK 0
#define DIRECT_MARK 1
#define DROP_MARK 2
#define REDIRECT_MARK 3
#define SYMMETRIC_NAT 4
#define REDIRECT_NETNS_MARK 5

#define ACTION_MASK 0x00FF
#define INDEX_MASK 0xFF00

#define FLOW_KEEP_GOING 0
#define FLOW_DIRECT 1
#define FLOW_DROP 2
#define FLOW_REDIRECT 3
#define FLOW_ALLOW_REUSE 4

#define FLOW_ID_MASK 0x000000FF
#define FLOW_ACTION_MASK 0x0000FF00

// 替换 FLOW_ID_MASK 对应的 0~7 位
static __always_inline u32 replace_flow_id(u32 original, u8 new_id) {
    original &= ~FLOW_ID_MASK;         // 清除原来的 ID 部分
    original |= ((u32)new_id & 0xFF);  // 设置新的 ID 部分
    return original;
}

// 替换 FLOW_ACTION_MASK 对应的 8~15 位
static __always_inline u32 replace_flow_action(u32 original, u8 new_action) {
    original &= ~FLOW_ACTION_MASK;              // 清除原来的 Action 部分
    original |= ((u32)new_action & 0xFF) << 8;  // 设置新的 Action 部分
    return original;
}

static __always_inline u8 get_flow_id(u32 original) { return (original & FLOW_ID_MASK); }

static __always_inline u8 get_flow_action(u32 original) {
    return (original & FLOW_ACTION_MASK) >> 8;
}

#define PRINT_MAC_ADDR(mac)                                                                        \
    bpf_log_info("mac: %02x:%02x:%02x:%02x:%02x:%02x", (mac)[0], (mac)[1], (mac)[2], (mac)[3],     \
                 (mac)[4], (mac)[5])

static __always_inline int _validate_read(struct __sk_buff *skb, void **hdr_, u32 offset, u32 len) {
    u8 *data = (u8 *)(__u64)skb->data;
    u8 *data_end = (u8 *)(__u64)skb->data_end;
    u8 *hdr = (u8 *)(data + offset);

    // ensure hdr pointer is on it's own for validation to work
    barrier_var(hdr);
    if (hdr + len > data_end) {
        if (bpf_skb_pull_data(skb, offset + len)) {
            return 1;
        }

        data = (u8 *)(__u64)skb->data;
        data_end = (u8 *)(__u64)skb->data_end;
        hdr = (u8 *)(data + offset);
        if (hdr + len > data_end) {
            return 1;
        }
    }

    *hdr_ = (void *)hdr;

    return 0;
}

#define VALIDATE_READ_DATA(skb, hdr, off, len) (_validate_read(skb, (void **)hdr, off, len))

struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    struct in6_addr addr;
};

struct ipv4_mark_action {
    __u32 mark;
};

static int prepend_dummy_mac(struct __sk_buff *skb) {
    char mac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0x00};

    if (bpf_skb_change_head(skb, 14, 0)) return -1;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

#endif /* __LD_LANDSCAPE_H__ */