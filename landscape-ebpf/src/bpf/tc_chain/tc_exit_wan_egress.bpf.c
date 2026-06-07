#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "chain/tc_cb.h"
#include "chain/tc_wan_exit_maps.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/egress")
int tc_exit_wan_egress_redirect(struct __sk_buff *skb) { return TC_ACT_OK; }
