#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "route/route_packet.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 current_l3_offset = 14;

struct route_packet_test_result {
    struct packet_offset_info offset;
    struct route_context_v4 v4;
    struct route_context_v6 v6;
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
            result.read_ret = read_route_context_v4_from_scan(skb, &result.offset, &result.v4);
            result.forward_ret = result.read_ret == TC_ACT_OK ? route_should_forward_v4(&result.v4)
                                                              : result.read_ret;
        } else if (result.offset.l3_protocol == LANDSCAPE_IPV6_TYPE) {
            result.read_ret = read_route_context_v6_from_scan(skb, &result.offset, &result.v6);
            result.forward_ret = result.read_ret == TC_ACT_OK ? route_should_forward_v6(&result.v6)
                                                              : result.read_ret;
        }
    }

    bpf_map_update_elem(&route_packet_test_result_map, &key, &result, BPF_ANY);
    return result.forward_ret;
#undef BPF_LOG_TOPIC
}
