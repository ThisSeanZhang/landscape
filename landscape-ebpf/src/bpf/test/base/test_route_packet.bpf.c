#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "route/route4_context.h"
#include "route/route6_context.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct route_packet_test_result {
    struct packet_offset_info offset;
    struct route4_context v4;
    struct route6_context v6;
    int scan_ret;
    int read_ret;
    int forward_ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct route_packet_test_result);
} route_packet_test_result_map SEC(".maps");

SEC("tc/ingress")
int test_route_packet(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_route_packet"
    u32 key = 0;
    struct route_packet_test_result result = {0};

    result.scan_ret = scan_route_packet(skb, current_l3_offset, &result.offset);
    result.read_ret = result.scan_ret;
    result.forward_ret = result.scan_ret;

    if (result.scan_ret == LD_SCAN_OK) {
        if (result.offset.l3_protocol == LANDSCAPE_IPV4_TYPE) {
            result.read_ret = route4_read_context_from_scan(skb, &result.offset, &result.v4);
            result.forward_ret =
                result.read_ret == TC_ACT_OK
                    ? (is_broadcast_ip4(result.v4.daddr) ? TC_ACT_UNSPEC : TC_ACT_OK)
                    : result.read_ret;
        } else if (result.offset.l3_protocol == LANDSCAPE_IPV6_TYPE) {
            result.read_ret = route6_read_context_from_scan(skb, &result.offset, &result.v6);
            result.forward_ret =
                result.read_ret == TC_ACT_OK
                    ? (is_broadcast_ip6(result.v6.daddr.bytes) ? TC_ACT_UNSPEC : TC_ACT_OK)
                    : result.read_ret;
        }
    }

    bpf_map_update_elem(&route_packet_test_result_map, &key, &result, BPF_ANY);
    return result.forward_ret;
#undef BPF_LOG_TOPIC
}
