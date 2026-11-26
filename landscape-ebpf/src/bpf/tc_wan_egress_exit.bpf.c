#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "chain/tc_exit_redirect.h"

char LICENSE[] SEC("license") = "GPL";

// Default from-LAN chain exit. A native-PPPoE session swaps this program
// for tc_wan_pppoe_exit_redirect while it is active.
SEC("tc/egress")
int tc_wan_egress_exit_redirect(struct __sk_buff *skb) { return tc_exit_neigh4(skb); }
