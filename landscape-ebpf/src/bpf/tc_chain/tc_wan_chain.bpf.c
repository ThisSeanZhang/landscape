#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "pipeline/tc_wan_exit_maps.h"
#include "pipeline/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

#define TC_NEXT_SLOT 0

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_ingress_root_next_stage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

// manager inject
const volatile u32 current_ifindex = 0;
const volatile u32 current_l3_offset = 0;

SEC("tc/ingress")
int tc_wan_chain_ingress_root(struct __sk_buff *skb) {
    // 不需要注入， wan ingress 如果最后是当前主机的就直接 OK, 不是就按照 target 转发就行
    skb->cb[TC_CHAIN_CB_L3_OFFSET] = current_l3_offset;
    bpf_tail_call(skb, &wan_ingress_root_next_stage, TC_NEXT_SLOT);
    bpf_tail_call(skb, &tc_pipe_exits_wan_ingress, TC_NEXT_SLOT);
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_wan_chain_egress_root(struct __sk_buff *skb) {
    skb->cb[TC_CHAIN_CB_TARGET_OFFSET] = current_ifindex;
    skb->cb[TC_CHAIN_CB_L3_OFFSET] = current_l3_offset;
    bpf_tail_call(skb, &wan_egress_root_next_stage, TC_NEXT_SLOT);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_OK;
}
