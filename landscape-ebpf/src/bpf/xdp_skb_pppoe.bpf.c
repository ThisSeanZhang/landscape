#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/xdp_meta.h"
#include "chain/wan_dispatch.h"

#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES bpf_htons(0x8864)
#endif

#define ETH_P_PPP_IPV4 bpf_htons(0x0021)
#define ETH_P_PPP_IPV6 bpf_htons(0x0057)

struct __attribute__((packed)) pppoe_header {
    u8 version_and_type;
    u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
};

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dispatch_key);
    __type(value, struct dispatch_value);
    __uint(max_entries, WAN_DISPATCH_MAX_ENTRIES);
} wan_intro_dispatch_map SEC(".maps");

// SKB-mode PPPoE stripper, the WAN-ingress entry used when native XDP is not
// available on the attach interface.  Shares the WAN intro dispatch map with
// `wan_intro_dispatch`:
//
//   0x8864 + IP46 payload + registered session
//        → strip the 8-byte PPPoE/PPP header, rewrite the ethhdr and:
//            unicast inner → record the resolved chain id in XDP metadata
//                            (read by the TC ingress intro to enter the
//                            chain without re-running the IP selector
//                            lookup);
//            bcast/mcast inner → NO metadata: pppd semantics — the TC
//                            intro's miss path exempts such daddrs and
//                            passes the frame to the local stack.
//          XDP_PASS so the TC ingress intro dispatches the frame.
//   anything else (discovery, LCP, unregistered sessions, truncated frames)
//        → XDP_PASS with the frame unmodified. Unregistered sessions belong
//          to pppd: the kernel PPPoE layer decapsulates them on the virtual
//          ppp device, where the TC ingress intro re-dispatches by inner IP.
SEC("xdp")
int xdp_skb_pppoe(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "xdp_skb_pppoe"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != ETH_P_PPP_SES) {
        return XDP_PASS;
    }

    struct pppoe_header *pppoe = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe + 1) > data_end) {
        return XDP_PASS;
    }

    if (pppoe->protocol != ETH_P_PPP_IPV4 && pppoe->protocol != ETH_P_PPP_IPV6) {
        return XDP_PASS;
    }

    // Inner IP header bounds: truncated frames pass unmodified (malformed
    // packets are the kernel's business, and pppd's view of the session
    // stays intact).  Inner broadcast/multicast: pppd semantics — strip for
    // the local stack, never into a chain (no handoff metadata; the TC
    // intro's miss path exempts such daddrs).
    bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;
    bool to_stack = false;

    if (is_v6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(pppoe + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            to_stack = true;
        }
    } else {
        struct iphdr *iph = (struct iphdr *)(pppoe + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip4(iph->daddr))) {
            to_stack = true;
        }
    }

    struct dispatch_key session_key = {
        .dispatch_type = WAN_INTRO_PPP_SESSION_TYPE,
        .ingress_ifindex = ctx->ingress_ifindex,
    };
    session_key.ppp.session_id = pppoe->session_id;

    struct dispatch_value *value = bpf_map_lookup_elem(&wan_intro_dispatch_map, &session_key);
    if (!value) {
        return XDP_PASS;
    }

    u16 l2_proto = is_v6 ? ETH_IPV6 : ETH_IPV4;

    u8 mac_pair[12];
    __builtin_memcpy(mac_pair, eth->h_dest, sizeof(mac_pair));

    int result = bpf_xdp_adjust_head(ctx, 8);
    if (result != 0) {
        ld_bpf_log("bpf_xdp_adjust_head failed: %d", result);
        return XDP_PASS;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }
    __builtin_memcpy(eth->h_dest, mac_pair, sizeof(mac_pair));
    eth->h_proto = l2_proto;

    if (!to_stack) {
        // Best-effort chain handoff. When the metadata cannot be stored (or
        // does not survive the XDP→skb transition), the TC ingress intro
        // still dispatches the stripped frame by its inner IP selector.
        xdp_set_ppp_chain_meta(ctx, value->chain_id);
    }

    return XDP_PASS;

#undef BPF_LOG_TOPIC
}
