#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

SEC("tc/egress")
int tc_wan_egress_root(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "tc_wan_egress_root <<<"
    bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_NEXT_SLOT);
    TC_CHAIN_EXIT_WAN_EGRESS(skb);
    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}
