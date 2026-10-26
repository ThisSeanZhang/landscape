#ifndef __LD_LANDSCAPE_H__
#define __LD_LANDSCAPE_H__
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include "base/printk.h"
#include "base/mark.h"
#include "base/tproxy.h"

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_REDIRECT 7

#define BPF_LOOP_RET_CONTINUE 0
#define BPF_LOOP_RET_BREAK 1

#define ETH_IPV4 bpf_htons(0x0800) /* ETH IPV4 packet */
#define ETH_IPV6 bpf_htons(0x86DD) /* ETH IPv6 packet */
#define ETH_ARP bpf_htons(0x0806)  /* ETH ARP packet */

#define AF_INET 2
#define AF_INET6 10

// L4 proto number
#define IPPROTO_ICMPV6 58

// timer
#define CLOCK_MONOTONIC 1

// LAND TYPE
#define LANDSCAPE_IPV4_TYPE 0
#define LANDSCAPE_IPV6_TYPE 1

#define PRINT_MAC_ADDR(mac)                                                                        \
    ld_log("mac: %02x:%02x:%02x:%02x:%02x:%02x", (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], \
           (mac)[5])

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define MAX_OFFSET 20480

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
    u8 mac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0x00};

    if (bpf_skb_change_head(skb, 14, 0)) return -1;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

static int prepend_dummy_mac_v6(struct __sk_buff *skb) {
    u8 mac[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x08, 0xdd};

    if (bpf_skb_change_head(skb, 14, 0)) return -1;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

static int store_mac_v4(struct __sk_buff *skb, u8 *dst_mac, u8 *src_mac) {
    u8 mac[14];

    __builtin_memcpy(mac, dst_mac, 6);
    __builtin_memcpy(mac + 6, src_mac, 6);

    mac[12] = 0x08;
    mac[13] = 0x00;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

static int store_mac_v6(struct __sk_buff *skb, u8 *dst_mac, u8 *src_mac) {
    u8 mac[14];

    __builtin_memcpy(mac, dst_mac, 6);
    __builtin_memcpy(mac + 6, src_mac, 6);

    mac[12] = 0x86;
    mac[13] = 0xdd;

    if (bpf_skb_store_bytes(skb, 0, mac, sizeof(mac), 0)) return -1;

    return 0;
}

struct inet_pair {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

static __always_inline bool is_zero_mac(const u8 *mac) {
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

static __always_inline int is_broadcast_mac(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    barrier_var(data);
    if (data + 6 > data_end) return TC_ACT_UNSPEC;

    u8 *mac = (u8 *)data;

    // 判断是否是广播地址 ff:ff:ff:ff:ff:ff
    bool is_broadcast = mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff &&
                        mac[4] == 0xff && mac[5] == 0xff;

    bool is_ipv6_broadcast = mac[0] == 0x33 && mac[1] == 0x33;

    if (unlikely(is_broadcast || is_ipv6_broadcast)) {
        return TC_ACT_UNSPEC;
    } else {
        return TC_ACT_OK;
    }
}

static __always_inline bool is_broadcast_or_mcast_mac(const u8 dmac[6]) {
    bool is_broadcast = dmac[0] == 0xff && dmac[1] == 0xff && dmac[2] == 0xff && dmac[3] == 0xff &&
                        dmac[4] == 0xff && dmac[5] == 0xff;
    bool is_ipv6_mcast = dmac[0] == 0x33 && dmac[1] == 0x33;
    return is_broadcast || is_ipv6_mcast;
}

#define IP_MULTICAST_MASK_NBO bpf_ntohl(0xF0000000)
#define IP_MULTICAST_BASE_NBO bpf_ntohl(0xE0000000)

static __always_inline bool is_broadcast_ip4(__be32 daddr) {
    // 255.255.255.255 or 0.0.0.0 (network byte order)
    if (daddr == 0xffffffff || daddr == 0) {
        return true;
    }
    if ((daddr & IP_MULTICAST_MASK_NBO) == IP_MULTICAST_BASE_NBO) {
        return true;
    }
    return false;
}

static __always_inline bool is_broadcast_ip6(const u8 *bytes) {
    __u8 first_byte = bytes[0];

    // IPv6 multicast ff00::/8
    if (first_byte == 0xff) {
        return true;
    }

    // IPv6 link-local fe80::/10
    if (first_byte == 0xfe) {
        __u8 second_byte = bytes[1];
        if ((second_byte & 0xc0) == 0x80) {
            return true;
        }
    }

    return false;
}

static __always_inline bool is_broadcast_ip6_pair(const struct inet_pair *ip_pair) {
    return is_broadcast_ip6(ip_pair->src_addr.in6_u.u6_addr8) ||
           is_broadcast_ip6(ip_pair->dst_addr.in6_u.u6_addr8);
}

struct inet4_addr {
    __be32 addr;
};

struct inet4_pair {
    struct inet4_addr src_addr;
    struct inet4_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

struct inet6_pair {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

static __always_inline bool inet4_addr_equal(const struct inet4_addr *a,
                                             const struct inet4_addr *b) {
    return a->addr == b->addr;
}

static __always_inline bool inet6_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
    return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
           a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
           a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
           a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

static __always_inline bool ip_addr_is_zero(const struct in6_addr *a) {
    return a->in6_u.u6_addr32[0] == 0 && a->in6_u.u6_addr32[1] == 0 && a->in6_u.u6_addr32[2] == 0 &&
           a->in6_u.u6_addr32[3] == 0;
}

static __always_inline bool ip_addr_is_zero_in6(const struct in6_addr *a) {
    return a->in6_u.u6_addr32[0] == 0 && a->in6_u.u6_addr32[1] == 0 && a->in6_u.u6_addr32[2] == 0 &&
           a->in6_u.u6_addr32[3] == 0;
}

static __always_inline bool ip_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
    return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
           a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
           a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
           a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

static __always_inline bool ip_addr_equal_in6(const struct in6_addr *a, const struct in6_addr *b) {
    return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
           a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
           a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
           a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

static __always_inline bool ip_addr_equal_x(const struct in6_addr *a, const struct in6_addr *b) {
    return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
           a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
           a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
           a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

#define COPY_ADDR_FROM(t, s) (__builtin_memcpy((t), (s), sizeof(t)))

static __always_inline int current_l3_protocol(struct __sk_buff *skb, u32 current_l3_offset,
                                               u8 *l3_protocol) {
    u32 need = current_l3_offset != 0 ? sizeof(struct ethhdr) : 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    barrier_var(data);
    if (data + need > data_end) return TC_ACT_SHOT;

    if (current_l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if (eth->h_proto == ETH_IPV4) {
            *l3_protocol = LANDSCAPE_IPV4_TYPE;
        } else if (eth->h_proto == ETH_IPV6) {
            *l3_protocol = LANDSCAPE_IPV6_TYPE;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 ip_version = (*(u8 *)data) >> 4;
        if (ip_version == 4) {
            *l3_protocol = LANDSCAPE_IPV4_TYPE;
        } else if (ip_version == 6) {
            *l3_protocol = LANDSCAPE_IPV6_TYPE;
        } else {
            return TC_ACT_UNSPEC;
        }
    }

    return TC_ACT_OK;
}

static __always_inline int current_pkg_type(struct __sk_buff *skb, u32 current_l3_offset,
                                            bool *is_ipv4_) {
    u8 l3_protocol = 0;
    int ret = current_l3_protocol(skb, current_l3_offset, &l3_protocol);
    if (ret != TC_ACT_OK) return TC_ACT_UNSPEC;

    bool is_ipv4 = l3_protocol == LANDSCAPE_IPV4_TYPE;
    *is_ipv4_ = is_ipv4;
    return TC_ACT_OK;
}

static __always_inline bool is_broadcast_ip4_pair(const struct inet4_pair *ip_pair) {
    return is_broadcast_ip4(ip_pair->src_addr.addr) || is_broadcast_ip4(ip_pair->dst_addr.addr);
}

#endif /* __LD_LANDSCAPE_H__ */
