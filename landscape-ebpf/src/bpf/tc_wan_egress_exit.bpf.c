#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "chain/tc_cb.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc/egress")
int tc_wan_egress_exit_redirect(struct __sk_buff *skb) {
    if (skb->cb[2] != TC_CB_NEIGH4_PENDING) return TC_ACT_UNSPEC;

    struct bpf_redir_neigh nh = {.nh_family = AF_INET, .ipv4_nh = skb->cb[3]};
    skb->cb[2] = TC_CB_NEIGH4_REDIRECT;
    if (nh.ipv4_nh) return bpf_redirect_neigh(skb->cb[4], &nh, sizeof(nh), 0);
    return bpf_redirect_neigh(skb->cb[4], NULL, 0, 0);
}
