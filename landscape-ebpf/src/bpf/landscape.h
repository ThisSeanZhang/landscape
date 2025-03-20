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

#endif /* __LD_LANDSCAPE_H__ */