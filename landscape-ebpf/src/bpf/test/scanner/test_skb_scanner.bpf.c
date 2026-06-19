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
