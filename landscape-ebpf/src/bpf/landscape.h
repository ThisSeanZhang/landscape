#ifndef __LD_LANDSCAPE_H__
#define __LD_LANDSCAPE_H__

#include "landscape_log.h"
#include "base/mark.h"
#include "base/tp.h"

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
    bpf_log_info("mac: %02x:%02x:%02x:%02x:%02x:%02x", (mac)[0], (mac)[1], (mac)[2], (mac)[3],     \
                 (mac)[4], (mac)[5])

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define MAX_OFFSET 20480

static __always_inline int _validate_read(struct __sk_buff *skb, void **hdr_, u32 offset, u32 len) {
    if (unlikely(offset > MAX_OFFSET || len > 256 || offset + len > MAX_OFFSET)) return 1;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *hdr = data + offset;

    barrier_var(hdr);
    if (likely(hdr + len <= data_end)) {
        *hdr_ = hdr;
        return 0;
    }

    if (bpf_skb_pull_data(skb, offset + len)) return 1;

    data = (void *)(long)skb->data;
    hdr = data + offset;

    if (hdr + len > (void *)(long)skb->data_end) return 1;

    *hdr_ = hdr;
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

// ICMPv4 消息类型
enum {
    ICMP_ERROR_MSG,
    ICMP_QUERY_MSG,
    ICMP_ACT_UNSPEC,
    ICMP_ACT_SHOT,
};

union u_inet_addr {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bits[16];
};

// only for ipv6
union u_inet6_addr {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bytes[16];
};

struct inet_pair {
    union u_inet_addr src_addr;
    union u_inet_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

/// 作为 fragment 缓存的 key
struct fragment_cache_key {
    u8 _pad[2];
    u8 l3proto;
    u8 l4proto;
    u32 id;
    union u_inet_addr saddr;
    union u_inet_addr daddr;
};

struct fragment_cache_value {
    u16 sport;
    u16 dport;
};

static __always_inline int is_broadcast_mac(struct __sk_buff *skb) {
    u8 *mac;

    if (VALIDATE_READ_DATA(skb, &mac, 0, 6)) {
        return TC_ACT_UNSPEC;
    }

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

static __always_inline int is_broadcast_ip4(__be32 dst) {
    // 255.255.255.255 or 0.0.0.0 (network byte order)
    if (dst == 0xffffffff || dst == 0) {
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_OK;
}

static __always_inline int is_broadcast_ip6(const u8 *bytes) {
    bool is_ipv6_broadcast = false;
    bool is_ipv6_locallink = false;

    __u8 first_byte = bytes[0];

    // IPv6 multicast ff00::/8
    if (first_byte == 0xff) {
        is_ipv6_broadcast = true;
    }

    // IPv6 link-local fe80::/10
    if (first_byte == 0xfe) {
        __u8 second_byte = bytes[1];
        if ((second_byte & 0xc0) == 0x80) {  // top 2 bits == 10
            is_ipv6_locallink = true;
        }
    }

    if (unlikely(is_ipv6_broadcast || is_ipv6_locallink)) {
        return TC_ACT_UNSPEC;
    } else {
        return TC_ACT_OK;
    }
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

union inet6_addr {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bytes[16];
};

struct inet6_pair {
    union inet6_addr src_addr;
    union inet6_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
};

static __always_inline bool inet4_addr_equal(const struct inet4_addr *a,
                                             const struct inet4_addr *b) {
    return a->addr == b->addr;
}

static __always_inline bool inet6_addr_equal(const union inet6_addr *a, const union inet6_addr *b) {
    return a->all[0] == b->all[0] && a->all[1] == b->all[2] && a->all[2] == b->all[2] &&
           a->all[3] == b->all[3];
}

static __always_inline bool ip_addr_equal(const union u_inet_addr *a, const union u_inet_addr *b) {
    return a->all[0] == b->all[0] && a->all[1] == b->all[1] && a->all[2] == b->all[2] &&
           a->all[3] == b->all[3];
}

#define COPY_ADDR_FROM(t, s) (__builtin_memcpy((t), (s), sizeof(t)))

static __always_inline int current_pkg_type(struct __sk_buff *skb, u32 current_l3_offset,
                                            bool *is_ipv4_) {
    bool is_ipv4;
    if (current_l3_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_UNSPEC;
        }

        if (eth->h_proto == ETH_IPV4) {
            is_ipv4 = true;
        } else if (eth->h_proto == ETH_IPV6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version == 4) {
            is_ipv4 = true;
        } else if (ip_version == 6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    }
    *is_ipv4_ = is_ipv4;
    return TC_ACT_OK;
}

static __always_inline int is_broadcast_ip4_pair(const struct inet4_pair *ip_pair) {
    if (is_broadcast_ip4(ip_pair->src_addr.addr)) {
        return TC_ACT_UNSPEC;
    } else if (is_broadcast_ip4(ip_pair->dst_addr.addr)) {
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_OK;
}

#endif /* __LD_LANDSCAPE_H__ */