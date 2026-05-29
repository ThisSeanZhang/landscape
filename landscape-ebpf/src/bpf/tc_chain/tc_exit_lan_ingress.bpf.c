#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "pipeline/tc_cb.h"
#include "pipeline/tc_lan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/ingress")
int tc_exit_lan_ingress_redirect(struct __sk_buff *skb) {
    u32 target = skb->cb[TC_CHAIN_CB_TARGET_OFFSET];
    u32 current = skb->ingress_ifindex;

    if (target == 0 || target == current) return TC_ACT_OK;

    return bpf_redirect(target, 0);
}
