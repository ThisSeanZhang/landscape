#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"

#include "chain/tc_cb.h"
#include "chain/wan_dispatch.h"
#include "tc_chain/tc_handoff.h"

// NOTE: this intro never parses PPPoE. Stripped session frames arrive as
// plain eth:IP (carrying the PPP-chain handoff metadata written by the
// SKB-mode XDP stripper), and pppd-owned frames are decapsulated by the
// kernel on the virtual ppp device where a separately attached instance of
// this intro (current_l3_offset = 0) re-dispatches by inner IP.
//
// Miss policy: an IPv4 unicast matching no selector is dropped (WAN junk,
// including decapped session frames whose handoff metadata did not
// survive); broadcast/multicast daddrs and IPv6 keep flowing to the stack.

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_l3_offset = 14;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, XDP_PIPE_MAX_ENTRIES);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tc_pipe_root_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dispatch_key);
    __type(value, struct dispatch_value);
    __uint(max_entries, WAN_DISPATCH_MAX_ENTRIES);
} wan_intro_dispatch_map SEC(".maps");

// Dispatch by the selector key. Returns the verdict for the miss case: an
// IPv4 unicast matching no selector is WAN junk → TC_ACT_SHOT; IPv6 keeps
// flowing to the stack because v6 selector binding does not exist yet
// (dropping it now would blackhole IPv6). Broadcast/multicast daddrs never
// reach this function — the caller exempts them before the lookup (DHCP
// replies, IGMP/MLD must reach the local stack).
static __always_inline int tc_intro_dispatch(struct __sk_buff *skb, struct dispatch_key *key) {
    struct dispatch_value *value = bpf_map_lookup_elem(&wan_intro_dispatch_map, key);
    if (!value) {
        return key->dispatch_type == LANDSCAPE_IPV4_TYPE ? TC_ACT_SHOT : TC_ACT_OK;
    }
    tc_cb_set_chain_id(skb, value->chain_id);
    bpf_tail_call(skb, &tc_pipe_root_progs, value->chain_id);
    // Chain root absent (e.g. the selector was registered before the chain
    // root got installed): the dispatch already happened (cb is set), keep
    // the frame flowing instead of blackholing link traffic during the race.
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_wan_intro(struct __sk_buff *skb) {
    // PPP chain handoff: the SKB-mode XDP stripper already resolved the
    // session's chain — enter it directly, skipping the IP selector lookup.
    // When the chain root is absent the tail call falls through and the IP
    // dispatch below acts as the fallback.
    u32 ppp_chain = tc_read_ppp_chain_handoff(skb);
    if (ppp_chain != 0) {
        tc_cb_set_chain_id(skb, ppp_chain);
        bpf_tail_call(skb, &tc_pipe_root_progs, ppp_chain);
    }

    int handoff_ret = xdp_handoff_check(skb, false);
    if (handoff_ret != TC_ACT_OK) return handoff_ret;

    struct dispatch_key key = {};
    bool is_ipv4;
    int ret;

    ret = current_pkg_type(skb, current_l3_offset, &is_ipv4);
    if (ret != TC_ACT_OK) return TC_ACT_OK;

    key.ingress_ifindex = skb->ingress_ifindex;

    if (is_ipv4) {
        struct iphdr *iph;
        if (VALIDATE_READ_DATA(skb, &iph, current_l3_offset, sizeof(*iph))) return TC_ACT_OK;

        // Broadcast/multicast destinations can never match a selector and
        // must reach the local stack (DHCP replies, IGMP): exempt them
        // before the dispatch lookup.
        if (unlikely(is_broadcast_ip4(iph->daddr))) return TC_ACT_OK;

        key.dispatch_type = LANDSCAPE_IPV4_TYPE;
        key.v4.daddr = iph->daddr;
    } else {
        struct ipv6hdr *ip6h;
        if (VALIDATE_READ_DATA(skb, &ip6h, current_l3_offset, sizeof(*ip6h))) return TC_ACT_OK;

        key.dispatch_type = LANDSCAPE_IPV6_TYPE;
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
    }

    return tc_intro_dispatch(skb, &key);
}
