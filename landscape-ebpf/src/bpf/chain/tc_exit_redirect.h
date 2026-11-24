#ifndef __LD_TC_EXIT_REDIRECT_H_
#define __LD_TC_EXIT_REDIRECT_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "chain/tc_cb.h"

/* Shared terminal step: finish an IPv4 neighbour miss recorded by the
 * chain root.  Both the plain and the PPPoE exit run it after their own
 * terminal work. */
static __always_inline int tc_exit_neigh4(struct __sk_buff *skb) {
    if (skb->cb[2] != TC_CB_NEIGH4_PENDING) return TC_ACT_UNSPEC;

    struct bpf_redir_neigh nh = {.nh_family = AF_INET, .ipv4_nh = skb->cb[3]};
    skb->cb[2] = TC_CB_NEIGH4_REDIRECT;
    if (nh.ipv4_nh) return bpf_redirect_neigh(skb->cb[4], &nh, sizeof(nh), 0);
    return bpf_redirect_neigh(skb->cb[4], NULL, 0, 0);
}

#endif /* __LD_TC_EXIT_REDIRECT_H_ */
