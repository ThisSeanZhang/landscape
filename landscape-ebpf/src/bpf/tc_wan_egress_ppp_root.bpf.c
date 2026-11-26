#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

SEC("tc/egress")
int tc_wan_egress_ppp_root(struct __sk_buff *skb) {
    skb->cb[2] = 0;

    // Legacy HostDirect lanes ride the ppp terminal without policy stages.
    if (is_skip_route_and_stage(skb_mark(skb))) return TC_ACT_UNSPEC;

    u32 proto = skb->protocol;
    if (proto == ETH_IPV4) {
        bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V4);
    } else if (proto == ETH_IPV6) {
        bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V6);
    }
    return TC_ACT_UNSPEC;
}
