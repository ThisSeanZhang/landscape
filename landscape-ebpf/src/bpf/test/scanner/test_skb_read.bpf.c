#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/skb_common.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct skb_read_test_result {
    u8 l3_proto;
    u8 _pad[3];
    int scan_ret;
    int read_l3_ret;
    int read_info_ret;
    struct scan_ipv4_idx v4_idx;
    struct scan_ipv6_idx v6_idx;
    u32 v4_l3_saddr;
    u32 v4_l3_daddr;
    u32 v6_l3_saddr[4];
    u32 v6_l3_daddr[4];
    struct inet4_pair v4_info;
    struct inet_pair v6_info;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct skb_read_test_result);
} skb_read_test_map SEC(".maps");

SEC("tc/ingress")
int test_skb_read(struct __sk_buff *skb) {
    u32 key = 0;
    struct skb_read_test_result *result = bpf_map_lookup_elem(&skb_read_test_map, &key);
    if (!result) return TC_ACT_OK;

    __builtin_memset(result, 0, sizeof(*result));

    u8 l3_proto = 0;
    int ret = current_l3_protocol(skb, current_l3_offset, &l3_proto);
    if (ret != TC_ACT_OK) {
        result->l3_proto = 0;
        result->scan_ret = ret;
        result->read_l3_ret = ret;
        result->read_info_ret = ret;
        return TC_ACT_OK;
    }

    result->l3_proto =
        l3_proto == LANDSCAPE_IPV4_TYPE ? 4 : (l3_proto == LANDSCAPE_IPV6_TYPE ? 6 : 0);

    if (l3_proto == LANDSCAPE_IPV4_TYPE) {
        result->scan_ret = (int)scan_ipv4_full(skb, current_l3_offset, &result->v4_idx);

        if (result->scan_ret == LD_SCAN_OK) {
            result->read_l3_ret = skb_read_ipv4_l3(skb, current_l3_offset, &result->v4_l3_saddr,
                                                   &result->v4_l3_daddr);
            result->read_info_ret =
                skb_read_ipv4_info(skb, current_l3_offset, &result->v4_idx, &result->v4_info);
        } else {
            result->read_l3_ret = result->scan_ret;
            result->read_info_ret = result->scan_ret;
        }
    } else if (l3_proto == LANDSCAPE_IPV6_TYPE) {
        result->scan_ret = (int)scan_ipv6_full(skb, current_l3_offset, &result->v6_idx);

        if (result->scan_ret == LD_SCAN_OK) {
            union u_inet6_addr saddr, daddr;
            result->read_l3_ret = skb_read_ipv6_l3(skb, current_l3_offset, &saddr, &daddr);
            __builtin_memcpy(result->v6_l3_saddr, saddr.all, sizeof(result->v6_l3_saddr));
            __builtin_memcpy(result->v6_l3_daddr, daddr.all, sizeof(result->v6_l3_daddr));
            result->read_info_ret =
                skb_read_ipv6_info(skb, current_l3_offset, &result->v6_idx, &result->v6_info);
        } else {
            result->read_l3_ret = result->scan_ret;
            result->read_info_ret = result->scan_ret;
        }
    }

    return TC_ACT_OK;
}
