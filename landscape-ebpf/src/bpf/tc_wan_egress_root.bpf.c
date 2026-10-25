#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "chain/tc_wan_exit_maps.h"
#include "chain/tc_cb.h"
#include "reader/tc_ferry_root.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} wan_egress_root_next_stage SEC(".maps");

const volatile u32 current_l3_offset = 14;

SEC("tc/egress")
int tc_wan_egress_root(struct __sk_buff *skb) {
    u8 l3_protocol = 0;
    if (current_l3_protocol(skb, current_l3_offset, &l3_protocol) == TC_ACT_OK) {
        if (l3_protocol == LANDSCAPE_IPV6_TYPE) {
            ferry_root_pack_v6(skb, current_l3_offset, LAND_NAT_FRAG_FROM_LAN);
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V6);
        } else {
            ferry_root_pack_v4(skb, current_l3_offset, LAND_NAT_FRAG_FROM_LAN);
            bpf_tail_call_static(skb, &wan_egress_root_next_stage, TC_SLOT_V4);
        }
    }

    ld_from_wan_log("ROOT next-stage tail FAILED (l3 %u) -> exit", l3_protocol);
    TC_FROM_LAN_CHAIN_EXIT(skb);
    return TC_ACT_UNSPEC;
}
