#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/skb_common.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct skb_scan_test_result {
    u8 scan_ret;
    u8 l3_proto;
    u8 _pad[2];
    struct scan_ipv4_idx v4;
    struct scan_ipv6_idx v6;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct skb_scan_test_result);
} skb_scan_test_map SEC(".maps");

SEC("tc/ingress")
int test_skb_scanner(struct __sk_buff *skb) {
    u32 key = 0;
    struct skb_scan_test_result *result = bpf_map_lookup_elem(&skb_scan_test_map, &key);
    if (!result) return TC_ACT_OK;

    __builtin_memset(result, 0, sizeof(*result));

    u8 l3_proto = 0;
    int ret = current_l3_protocol(skb, current_l3_offset, &l3_proto);
    if (ret != TC_ACT_OK) {
        result->l3_proto = 0;
        result->scan_ret = (u8)ret;
        return TC_ACT_OK;
    }

    result->l3_proto =
        l3_proto == LANDSCAPE_IPV4_TYPE ? 4 : (l3_proto == LANDSCAPE_IPV6_TYPE ? 6 : 0);

    if (l3_proto == LANDSCAPE_IPV4_TYPE) {
        result->scan_ret = (u8)scan_ipv4_full(skb, current_l3_offset, &result->v4);
    } else if (l3_proto == LANDSCAPE_IPV6_TYPE) {
        result->scan_ret = (u8)scan_ipv6_full(skb, current_l3_offset, &result->v6);
    }

    return TC_ACT_OK;
}

struct skb_icmp_test_result {
    u8 scan_ret;
    u8 l3_proto;
    u8 _pad[2];
    u16 icmp_error_l3_offset;
    u16 icmp_error_inner_l4_offset;
    u8 icmp_error_l4_protocol;
    u8 pkt_type;
    __be32 v4_saddr;
    struct in6_addr v6_saddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct skb_icmp_test_result);
} skb_scan_icmp_map SEC(".maps");

SEC("tc")
int test_skb_scanner_icmp(struct __sk_buff *skb) {
    u32 key = 0;
    struct skb_icmp_test_result *r = bpf_map_lookup_elem(&skb_scan_icmp_map, &key);
    if (!r) return TC_ACT_OK;

    __builtin_memset(r, 0, sizeof(*r));

    u8 l3_proto = 0;
    int ret = current_l3_protocol(skb, current_l3_offset, &l3_proto);
    if (ret != TC_ACT_OK) {
        r->l3_proto = 0;
        r->scan_ret = (u8)ret;
        return TC_ACT_OK;
    }

    r->l3_proto = l3_proto == LANDSCAPE_IPV4_TYPE ? 4 : (l3_proto == LANDSCAPE_IPV6_TYPE ? 6 : 0);

    if (l3_proto == LANDSCAPE_IPV4_TYPE) {
        struct scan_ipv4_idx idx = {};
        ret = scan_ipv4_into_idx(skb, current_l3_offset, &idx);
        if (ret != LD_SCAN_OK) {
            r->scan_ret = (u8)ret;
            return TC_ACT_OK;
        }

        r->pkt_type = idx.pkt_type;
        bool upgraded = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMP)
            upgraded = scan_ipv4_upgrade_icmp(skb, current_l3_offset, &idx, &r->v4_saddr);

        r->icmp_error_l3_offset = idx.icmp_error_l3_offset;
        r->icmp_error_inner_l4_offset = idx.icmp_error_inner_l4_offset;
        r->icmp_error_l4_protocol = idx.icmp_error_l4_protocol;
        if (!upgraded) r->v4_saddr = 0;

        r->scan_ret = (u8)LD_SCAN_OK;
    } else if (l3_proto == LANDSCAPE_IPV6_TYPE) {
        struct scan_ipv6_idx idx = {};
        ret = scan_ipv6_into_idx(skb, current_l3_offset, &idx);
        if (ret != LD_SCAN_OK) {
            r->scan_ret = (u8)ret;
            return TC_ACT_OK;
        }

        r->pkt_type = idx.pkt_type;
        bool upgraded = false;
        if (idx.fragment_type < FRAG_MIDDLE && idx.l4_protocol == IPPROTO_ICMPV6)
            upgraded = scan_ipv6_upgrade_icmp(skb, current_l3_offset, &idx, &r->v6_saddr);

        r->icmp_error_l3_offset = idx.icmp_error_l3_offset;
        r->icmp_error_inner_l4_offset = idx.icmp_error_inner_l4_offset;
        r->icmp_error_l4_protocol = idx.icmp_error_l4_protocol;
        if (!upgraded) __builtin_memset(&r->v6_saddr, 0, sizeof(r->v6_saddr));

        r->scan_ret = (u8)LD_SCAN_OK;
    }

    return TC_ACT_OK;
}
