#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "chain/tc_cb.h"
#include "chain/tc_handoff.h"
#include "map/wan_trie.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_root_progs SEC(".maps");

/* WAN dispatch trie shared with the XDP seed (reuse_fd before load).
 * Dispatch roots are tc_pipe_root_progs slots, indexed by the owning WAN
 * link's chain id.
 */
WAN_TRIE_DECLARE(wan_trie_arena, wan_trie_tbl);

static __always_inline void tc_intro_dispatch(struct __sk_buff *skb, u64 key) {
    u32 root = wan_trie_resolve(&wan_trie_tbl, key);
    if (root) {
        bpf_tail_call(skb, &tc_pipe_root_progs, root);
    }
}

SEC("tc/ingress")
int tc_wan_ingress_intro(struct __sk_buff *skb) {
    int handoff_ret = xdp_handoff_check(skb, false);
    if (handoff_ret != TC_ACT_OK) return handoff_ret;

    u64 key64 = 0;
    bool is_ipv4;
    int ret;

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (ret != TC_ACT_OK) return TC_ACT_OK;

    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) return TC_ACT_OK;

        if (unlikely(is_broadcast_ip4(iph->daddr))) {
            return TC_ACT_OK;
        }

        key64 = wan_trie_key_v4(iph->daddr);
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) return TC_ACT_OK;

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            return TC_ACT_OK;
        }

        __builtin_memcpy(&key64, &ip6h->daddr, sizeof(key64));
    }

    // The trie is the only dispatch authority: WAN links publish their
    // v4/v6 (and PPP) keys before this program can see their traffic.
    tc_intro_dispatch(skb, key64);

    return TC_ACT_SHOT;
}
