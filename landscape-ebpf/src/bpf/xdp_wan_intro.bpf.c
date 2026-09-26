#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"

#include "chain/xdp_meta.h"
#include "chain/wan_dispatch.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

#ifndef ETH_P_PPP_DISC
#define ETH_P_PPP_DISC bpf_htons(0x8863)
#endif

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

static __always_inline int wan_intro_store_chain_meta(struct xdp_md *ctx, u32 chain_id) {
    struct xdp_pipe_meta meta = {.chain_id = chain_id};
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(meta) <= data) {
        __builtin_memcpy(data_meta, &meta, sizeof(meta));
        return 0;
    }
    return xdp_set_meta(ctx, &meta);
}

static __always_inline int wan_intro_tailcall_root(struct xdp_md *ctx, struct dispatch_key *key) {
    struct dispatch_value *value = bpf_map_lookup_elem(&wan_intro_dispatch_map, key);
    if (!value) {
        // A plain IPv4 unicast matching no selector is WAN junk: drop it at
        // the earliest point. IPv6 keeps passing until v6 selector binding
        // exists (dropping it now would blackhole IPv6).
        return key->dispatch_type == LANDSCAPE_IPV4_TYPE ? XDP_DROP : XDP_PASS;
    }

    if (wan_intro_store_chain_meta(ctx, value->chain_id) != 0) return XDP_PASS;
    bpf_tail_call(ctx, &xdp_pipe_root_progs, value->chain_id);
    ld_bpf_log("wan_intro tail call failed, dispatch_type=%u chain_id=%u", key->dispatch_type,
               value->chain_id);
    return XDP_PASS;
}

SEC("xdp")
int wan_intro_dispatch(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "wan_intro_dispatch"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct dispatch_key key = {};

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    //
    // wan_intro_dispatch — WAN XDP ingress entry point
    //   Attached to WAN interfaces.  Classifies incoming packets and
    //   dispatches them into the WAN→LAN chain via xdp_pipe_root_progs.
    //   The LAN counterpart is xdp_lan_intro, attached to LAN interfaces.
    //
    //   │
    //   ├─ classifies IPv4 / IPv6 / PPPoE
    //   ├─ broadcast / multicast destinations → XDP_PASS (stack)
    //   ├─ looks up wan_intro_dispatch_map (scoped by ingress ifindex)
    //   │     ├─ miss  → XDP_DROP for IPv4 (WAN junk); IPv6 still passes
    //   │     │          until v6 selector binding exists
    //   │     └─ hit   → bpf_tail_call(&xdp_pipe_root_progs,
    //   │                        value->chain_id)
    //   │                    │
    //   │                    ▼  chain root (linked-list head)
    //   │                         │→ &next_stage[0] → ... → wan_route
    //   │                                                    │
    //   │                                              bpf_redirect()
    //   ├─ PPPoE session data → session selector lookup FIRST:
    //   │     ├─ miss  → XDP_PASS with the frame unmodified: pppd/kernel
    //   │     │          decapsulates it on the virtual ppp device, where
    //   │     │          the TC ingress intro re-dispatches by inner IP
    //   │     ├─ bcast/mcast inner → decap WITHOUT chain metadata: the
    //   │     │          frame reaches the local stack, never a chain
    //   │     └─ hit   → strips the session header, rewrites ethhdr,
    //   │                stores the chain id in XDP metadata, tail-calls
    //   └─ stores the selected chain id in XDP metadata for later stages
    //

    if (eth->h_proto == ETH_IPV4) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip4(iph->daddr))) {
            return XDP_PASS;
        }

        key.dispatch_type = LANDSCAPE_IPV4_TYPE;
        key.ingress_ifindex = ctx->ingress_ifindex;
        key.v4.daddr = iph->daddr;
        return wan_intro_tailcall_root(ctx, &key);
    }

    if (eth->h_proto == ETH_IPV6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            return XDP_PASS;
        }

        key.dispatch_type = LANDSCAPE_IPV6_TYPE;
        key.ingress_ifindex = ctx->ingress_ifindex;
        __builtin_memcpy(&key.v6.prefix64, &ip6h->daddr, sizeof(key.v6.prefix64));
        return wan_intro_tailcall_root(ctx, &key);
    }

    if (eth->h_proto != ETH_P_PPP_SES) {
        return XDP_PASS;
    }

    //
    // PPPoE session data frames: dispatch on the session selector only.
    //   hit  → strip the 8-byte PPPoE/PPP header, store the chain id in
    //          XDP metadata and tail-call the chain root.
    //   bcast/mcast inner → same strip, but NO metadata and no tail call:
    //          pppd semantics — decapsulated and handed to the local stack,
    //          never into a chain.
    //   miss → pass the frame UNMODIFIED. The session belongs to pppd (or
    //          its chain is not registered yet): the kernel PPPoE layer
    //          decapsulates it on the virtual ppp device, where the TC
    //          ingress intro re-dispatches by inner IP. Non-IP PPP
    //          protocols (LCP & friends) always take this path too.
    //
    struct pppoe_header *pppoe = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe + 1) > data_end) {
        return XDP_PASS;
    }

    if (pppoe->protocol != ETH_P_PPP_IPV4 && pppoe->protocol != ETH_P_PPP_IPV6) {
        return XDP_PASS;
    }

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

    if (to_stack) {
        // Decapsulated multicast/broadcast for the local stack: no chain
        // metadata (its absence keeps the TC intro's miss path on the bcast
        // exemption instead of the chain entry) and no tail call.
        return XDP_PASS;
    }

    if (wan_intro_store_chain_meta(ctx, value->chain_id) != 0) return XDP_PASS;
    bpf_tail_call(ctx, &xdp_pipe_root_progs, value->chain_id);
    ld_bpf_log("wan_intro ppp session tail call failed, chain_id=%u", value->chain_id);
    return XDP_PASS;

#undef BPF_LOG_TOPIC
}
