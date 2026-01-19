#ifndef __LD_FLOW_MATCH_H__
#define __LD_FLOW_MATCH_H__
#include <bpf/bpf_helpers.h>
#include "landscape.h"

#define FLOW_ENTRY_MODE_MAC 0
#define FLOW_ENTRY_MODE_IP 1

// IPV4 32 + 32 = 64
#define FLOW_IP_IPV4_MATCH_LEN 64
// IPV4 32 + 64 = 96
#define FLOW_IP_IPV6_MATCH_LEN 96

// IPV4 32 + 48 = 80
#define FLOW_MAC_MATCH_LEN 80

struct imac_addr {
    u8 mac[6];
};

struct flow_match_key {
    u32 prefixlen;
    // vlan id
    // u32 vlan_tci;
    // tos value
    // u8 tos;
    // IP 协议: IPv4 Ipv6
    u8 l3_protocol;
    // IP 层协议: TCP / UDP
    // u8 l4_protocol;

    // FLOW_ENTRY_MODE_MAC | FLOW_ENTRY_MODE_IP
    u8 is_match_ip;

    u8 _pad[2];
    union {
        // 源 IP 地址
        union u_inet_addr src_addr;
        // MAC
        struct imac_addr mac;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct flow_match_key);
    __type(value, u32);
    __uint(max_entries, 65536);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
} flow_match_map SEC(".maps");

static __always_inline int match_flow_id_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                            __be32 saddr, u32 *default_flow_id_) {
#define BPF_LOG_TOPIC "match_flow_id_v4"
    struct flow_match_key match_key = {0};
    u32 ret_flow_id = *default_flow_id_;

    if (current_l3_offset != 0) {
        u8 *mac;
        if (VALIDATE_READ_DATA(skb, &mac, 6, 6)) {
            bpf_log_info("read mac error");
            return TC_ACT_SHOT;
        }
        __builtin_memcpy(match_key.mac.mac, mac, 6);

        match_key.prefixlen = FLOW_MAC_MATCH_LEN;
        match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

        u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
        if (flow_id_ptr != NULL) {
            ret_flow_id = *flow_id_ptr;
            // if (ret_flow_id == 201) {
            //     bpf_log_info("find flow_id by MAC: %u, ip: %pI4", ret_flow_id, &saddr);
            //     PRINT_MAC_ADDR(match_key.mac.mac);
            // }
        }
    }

    match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    match_key.prefixlen = FLOW_IP_IPV4_MATCH_LEN;
    match_key.src_addr.ip = saddr;

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
        // if (ret_flow_id == 201) {
        //     bpf_log_info("find flow_id: %u, ip: %pI4", ret_flow_id, match_key.src_addr.all);
        // }
        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     bpf_log_info("find flow_id: %u, ip: %pI4", ret_flow_id, match_key.src_addr.all);
        // } else {
        //     bpf_log_info("find flow_id: %u, ip: %pI6", ret_flow_id, match_key.src_addr.all);
        // }
    }

    *default_flow_id_ = ret_flow_id;
    // bpf_log_info("flow_id: %u", ret_flow_id);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int match_flow_id_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                            const union u_inet6_addr *saddr,
                                            u32 *default_flow_id_) {
#define BPF_LOG_TOPIC "match_flow_id"
    struct flow_match_key match_key = {0};
    u32 ret_flow_id = *default_flow_id_;

    if (current_l3_offset != 0) {
        u8 *mac;
        if (VALIDATE_READ_DATA(skb, &mac, 6, 6)) {
            bpf_log_info("read mac error");
            return TC_ACT_SHOT;
        }
        __builtin_memcpy(match_key.mac.mac, mac, 6);

        match_key.prefixlen = FLOW_MAC_MATCH_LEN;
        match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

        u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
        if (flow_id_ptr != NULL) {
            ret_flow_id = *flow_id_ptr;
            // bpf_log_info("find flow_id by MAC: %u", ret_flow_id);
            // PRINT_MAC_ADDR(match_key.mac.mac);
        }
    }

    match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    match_key.prefixlen = FLOW_IP_IPV6_MATCH_LEN;
    COPY_ADDR_FROM(match_key.src_addr.all, saddr->bytes);

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     bpf_log_info("find flow_id: %u, ip: %pI4", ret_flow_id, match_key.src_addr.all);
        // } else {
        //     bpf_log_info("find flow_id: %u, ip: %pI6", ret_flow_id, match_key.src_addr.all);
        // }
    }

    *default_flow_id_ = ret_flow_id;
    // bpf_log_info("flow_id: %u", ret_flow_id);
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_FLOW_MATCH_H__ */