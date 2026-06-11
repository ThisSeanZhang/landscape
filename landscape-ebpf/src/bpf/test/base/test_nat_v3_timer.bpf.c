#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "land_nat4_v3.h"

char LICENSE[] SEC("license") = "GPL";

struct nat4_timer_test_input_v3 {
    struct nat_timer_key_v4 key;
    u8 force_queue_push_fail;
    u8 _pad[3];
};

struct nat4_timer_test_result_v3 {
    u32 action;
    s32 queue_push_ret;
    u64 next_timeout;
    u8 timer_exists;
    u8 ingress_mapping_exists;
    u8 egress_mapping_exists;
    u8 state_exists;
    u8 _pad0[4];
    u64 state_ref;
    u16 generation;
    u16 status;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct nat4_timer_test_input_v3);
    __uint(max_entries, 1);
} nat4_timer_test_input_v3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct nat4_timer_test_result_v3);
    __uint(max_entries, 1);
} nat4_timer_test_result_v3 SEC(".maps");

SEC("tc")
int nat_v4_timer_step_test(struct __sk_buff *skb) {
    u32 index = 0;
    struct nat4_timer_test_input_v3 *input = bpf_map_lookup_elem(&nat4_timer_test_input_v3, &index);
    struct nat4_timer_test_result_v3 *result =
        bpf_map_lookup_elem(&nat4_timer_test_result_v3, &index);
    if (!input || !result) {
        return TC_ACT_SHOT;
    }

    __builtin_memset(result, 0, sizeof(*result));
    result->queue_push_ret = -2;

    struct nat4_timer_value_v3 *value = bpf_map_lookup_elem(&nat4_mapping_timer_v3, &input->key);
    if (!value) {
        return TC_ACT_OK;
    }

    __be32 nat_addr = input->key.pair_ip.dst_addr.addr;
    __be16 nat_port = input->key.pair_ip.dst_port;
    __be32 client_addr = value->client_addr.addr;
    __be16 client_port = value->client_port;
    int queue_push_ret = -2;
    u64 next_timeout = 0;

    result->action = nat4_v3_handle_timer_step(&input->key, value, input->force_queue_push_fail,
                                               &queue_push_ret, &next_timeout);
    result->queue_push_ret = queue_push_ret;
    result->next_timeout = next_timeout;

    value = bpf_map_lookup_elem(&nat4_mapping_timer_v3, &input->key);
    result->timer_exists = value ? 1 : 0;
    if (value) {
        result->status = value->status;
    }

    struct nat_mapping_key_v4 ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = input->key.l4proto,
        .from_addr = nat_addr,
        .from_port = nat_port,
    };
    struct nat_mapping_key_v4 egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = input->key.l4proto,
        .from_addr = client_addr,
        .from_port = client_port,
    };

    result->ingress_mapping_exists = bpf_map_lookup_elem(&nat4_dyn_map, &ingress_key) ? 1 : 0;
    result->egress_mapping_exists = bpf_map_lookup_elem(&nat4_dyn_map, &egress_key) ? 1 : 0;

    struct nat4_mapping_value_v3 *ingress_value = bpf_map_lookup_elem(&nat4_dyn_map, &ingress_key);
    result->state_exists = ingress_value ? 1 : 0;
    if (ingress_value) {
        result->state_ref = ingress_value->state_ref;
        result->generation = ingress_value->generation;
    }

    return TC_ACT_OK;
}
