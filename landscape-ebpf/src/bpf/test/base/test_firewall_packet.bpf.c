#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "firewall/firewall_packet.h"
#include "pkg_fragment.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 current_l3_offset = 14;

struct firewall_packet_test_result {
    struct packet_offset_info offset;
    struct inet_pair ip_pair;
    int parse_ret;
    int frag_ret;
    int did_frag_track;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct firewall_packet_test_result);
} firewall_packet_test_result_map SEC(".maps");

SEC("tc/ingress")
int test_firewall_packet(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "test_firewall_packet"
    u32 key = 0;
    struct firewall_packet_test_result result = {0};

    result.parse_ret =
        extract_firewall_packet_info(skb, &result.offset, &result.ip_pair, current_l3_offset);
    if (result.parse_ret == TC_ACT_OK && !is_icmp_error_pkt(&result.offset)) {
        result.did_frag_track = 1;
        result.frag_ret = frag_info_track(&result.offset, &result.ip_pair);
    } else {
        result.frag_ret = result.parse_ret;
    }

    bpf_map_update_elem(&firewall_packet_test_result_map, &key, &result, BPF_ANY);
    return result.parse_ret == TC_ACT_OK ? result.frag_ret : result.parse_ret;
#undef BPF_LOG_TOPIC
}
