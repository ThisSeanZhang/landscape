#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "chain/tc_cb.h"
#include "chain/tc_handoff.h"
#include "chain/wan_intro_dispatch.h"

#define TC_INTRO_IFINDEX_TYPE 2

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_root_progs SEC(".maps");

static __always_inline void tc_intro_dispatch(struct __sk_buff *skb, struct dispatch_key *key) {
    struct dispatch_value *value = bpf_map_lookup_elem(&wan_intro_dispatch_map, key);
    if (!value) return;
    bpf_tail_call(skb, &tc_pipe_root_progs, value->next_pipe_root_index);
}

SEC("tc/ingress")
int tc_wan_ingress_intro(struct __sk_buff *skb) {
    int handoff_ret = xdp_handoff_check(skb, false);
    if (handoff_ret != TC_ACT_OK) return handoff_ret;

    struct dispatch_key key = {};
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

        key.dispatch_type = LANDSCAPE_IPV4_TYPE;
        key.v4.daddr = iph->daddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) return TC_ACT_OK;

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            return TC_ACT_OK;
        }

        key.dispatch_type = LANDSCAPE_IPV6_TYPE;
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
    }

    tc_intro_dispatch(skb, &key);

    key.v6.prefix64 = 0;
    key.dispatch_type = TC_INTRO_IFINDEX_TYPE;
    key.ifindex = skb->ingress_ifindex;
    tc_intro_dispatch(skb, &key);

    return TC_ACT_SHOT;
}
