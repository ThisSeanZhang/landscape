#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "pipeline/tc_cb.h"
#include "pipeline/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/egress")
int tc_exit_wan_egress_redirect(struct __sk_buff *skb) {
    u32 target = skb->cb[TC_CHAIN_CB_TARGET_OFFSET];
    u32 current = skb->ifindex;

    if (target == 0 || target == current) return TC_ACT_OK;

    skb->cb[TC_CHAIN_CB_ROUTE_DONE_OFFSET] = 1;
    return bpf_redirect(target, 0);
}
