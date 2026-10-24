// SPDX-License-Identifier: GPL-2.0-or-later
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "nat_v4/tc_nat4.h"

char LICENSE[] SEC("license") = "GPL";

struct napt_ct_timer_test_input {
    struct napt_ct_key key;
    __u8 force_queue_push_fail;
    __u8 pad[3];
};

struct napt_ct_timer_test_result {
    __u32 action;
    __s32 queue_push_ret;
    __u64 next_timeout;
    __u8 timer_exists;
    __u8 lan_exists;
    __u8 wan_exists;
    __u8 kind;
    __u64 state_ref;
    __u64 status;
    __u64 client_status;
    __u64 server_status;
    __u32 gen;
    __u32 external_port;
};

struct napt_ct_advance_test_input {
    struct napt_ct_key key;
    __u8 tcp_phase;
    __u8 gress;
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct napt_ct_timer_test_input);
    __uint(max_entries, 1);
} napt_ct_timer_test_input SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct napt_ct_timer_test_result);
    __uint(max_entries, 1);
} napt_ct_timer_test_result SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct napt_ct_advance_test_input);
    __uint(max_entries, 1);
} napt_ct_advance_test_input SEC(".maps");

static __always_inline struct napt_ct_timer_test_result *napt_test_result(void) {
    __u32 index = 0;
    return bpf_map_lookup_elem(&napt_ct_timer_test_result, &index);
}

SEC("tc")
int napt_ct_timer_step_test(struct __sk_buff *skb) {
    (void)skb;
    __u32 index = 0;
    struct napt_ct_timer_test_input *input = bpf_map_lookup_elem(&napt_ct_timer_test_input, &index);
    struct napt_ct_timer_test_result *result = napt_test_result();

    if (!input || !result) return TC_ACT_SHOT;

    __builtin_memset(result, 0, sizeof(*result));
    result->queue_push_ret = -2;

    struct napt_ct_value *value = bpf_map_lookup_elem(&napt_ct, &input->key);
    if (!value) return TC_ACT_OK;

    __u32 external_port = value->external_port;
    __u32 gen = value->from_wan_gen;
    int queue_push_ret = -2;
    __u64 next_timeout = 0;

    result->action = napt_ct_timer_step(&input->key, value, input->force_queue_push_fail,
                                        &queue_push_ret, &next_timeout);
    result->queue_push_ret = queue_push_ret;
    result->next_timeout = next_timeout;
    result->external_port = external_port;
    result->gen = gen;

    value = bpf_map_lookup_elem(&napt_ct, &input->key);
    result->timer_exists = value ? 1 : 0;
    if (value) {
        result->status = value->status;
        result->client_status = value->client_status;
        result->server_status = value->server_status;
    }

    struct napt_from_lan_value *lan =
        napt_lan_lookup(input->key.internal_addr, input->key.internal_port, input->key.proto);
    result->lan_exists = lan ? 1 : 0;

    struct napt_from_wan_value *wan = napt_wan_lookup(input->key.proto, external_port);
    result->wan_exists = wan ? 1 : 0;
    if (wan) {
        result->kind = wan->kind;
        result->state_ref = wan->state_ref;
        result->gen = wan->generation;
    }

    return TC_ACT_OK;
}

SEC("tc")
int napt_ct_advance_test(struct __sk_buff *skb) {
    (void)skb;
    __u32 index = 0;
    struct napt_ct_advance_test_input *input =
        bpf_map_lookup_elem(&napt_ct_advance_test_input, &index);
    struct napt_ct_timer_test_result *result = napt_test_result();

    if (!input || !result) return TC_ACT_SHOT;

    __builtin_memset(result, 0, sizeof(*result));

    struct napt_ct_value *value = bpf_map_lookup_elem(&napt_ct, &input->key);
    if (!value) return TC_ACT_SHOT;

    struct skb_ferry_cb cb = {};
    cb.l4_protocol = input->key.proto;
    cb.tcp_phase = input->tcp_phase;

    result->action = napt_ct_advance(&cb, input->gress, value);
    result->status = value->status;
    result->client_status = value->client_status;
    result->server_status = value->server_status;
    result->timer_exists = 1;
    return TC_ACT_OK;
}
