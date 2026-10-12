#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "tproxy/tproxy_packet.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct tproxy_packet_test_result {
    struct packet_offset_info offset;
    struct inet_pair pair;
    int scan_ret;
    int read_ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tproxy_packet_test_result);
} tproxy_packet_test_result_map SEC(".maps");

SEC("tc/ingress")
int test_tproxy_packet(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_tproxy_packet"
    u32 key = 0;
    struct tproxy_packet_test_result result = {0};

    result.scan_ret = scan_tproxy_packet(skb, current_l3_offset, &result.offset);
    result.read_ret = result.scan_ret;

    if (result.scan_ret == LD_SCAN_OK) {
        result.read_ret = read_tproxy_packet_info(skb, &result.offset, &result.pair);
    }

    bpf_map_update_elem(&tproxy_packet_test_result_map, &key, &result, BPF_ANY);
    return result.read_ret;
#undef BPF_LOG_TOPIC
}
