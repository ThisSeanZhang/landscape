#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

#define TC_NEXT_SLOT 0

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

SEC("tc/egress")
int tc_wan_chain_egress_root(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_wan_chain_egress_root <<<"
    bpf_tail_call(skb, &wan_egress_root_next_stage, TC_NEXT_SLOT);
    bpf_tail_call(skb, &tc_pipe_exits_wan_egress, TC_NEXT_SLOT);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}
