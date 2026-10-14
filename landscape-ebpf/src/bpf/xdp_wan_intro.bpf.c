#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"

#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "map/wan_trie.h"

char LICENSE[] SEC("license") = "GPL";

/* WAN dispatch trie in this program's own arena. libbpf re-copies the
 * ELF-initial (zero) arena data on every load, so the table is never
 * shared: the runtime registers the arena with the global WanTrieDispatcher
 * right after skeleton load — which publishes the current entry set — and
 * only then attaches the program.
 *
 * Dispatch roots are prog-array slots, indexed by the owning WAN link's
 * chain id.
 */
WAN_TRIE_DECLARE(wan_trie_arena, wan_trie_tbl);

static __always_inline void wan_intro_tailcall_root(struct xdp_md *ctx, u32 root_index) {
    bpf_tail_call(ctx, &xdp_pipe_root_progs, root_index);
    ld_bpf_log("wan_intro tail call failed, root_index=%u", root_index);
}

/* Primary key hit -> its chain root; miss -> XDP_PASS.  The trie is the
 * only dispatch authority: every WAN link publishes its v4/v6/PPP keys
 * (with its chain id as value) before this program can see its traffic.
 */
static __always_inline int wan_intro_dispatch(struct xdp_md *ctx, u64 key) {
    u32 root = wan_trie_resolve(&wan_trie_tbl, key);
    if (root) {
        wan_intro_tailcall_root(ctx, root);
    }
    return XDP_PASS;
}

SEC("xdp")
int xdp_wan_intro(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "xdp_wan_intro"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    //
    // xdp_wan_intro — WAN XDP ingress entry point
    //   Attached to WAN interfaces.  Classifies incoming packets and
    //   dispatches them into the WAN→LAN chain via xdp_pipe_root_progs.
    //   The LAN counterpart is xdp_lan_route, attached to LAN interfaces.
    //
    //   │
    //   ├─ classifies IPv4 / IPv6 / PPPoE
    //   ├─ PPPoE → strips session header, rewrites ethhdr
    //   ├─ resolves the WAN dispatch trie (one arena trie, namespaced keys:
    //   │     IPv6 prefix64 / IPv4 daddr / PPPoE session; values are chain
    //   │     ids published by the WAN link hub)
    //   │     ├─ miss  → XDP_PASS
    //   │     └─ hit   → bpf_tail_call(&xdp_pipe_root_progs, chain)
    //   │                    │
    //   │                    ▼  chain root (linked-list head)
    //   │                         │→ &next_stage[0] → ... → wan_route
    //   │                                                    │
    //   │                                              bpf_redirect()
    //   └─ does not write meta (dispatch only classifies / dispatches)
    //

    if (eth->h_proto == ETH_IPV4) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip4(iph->daddr))) {
            return XDP_PASS;
        }

        return wan_intro_dispatch(ctx, wan_trie_key_v4(iph->daddr));
    }

    if (eth->h_proto == ETH_IPV6) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) {
            return XDP_PASS;
        }

        if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
            return XDP_PASS;
        }

        u64 prefix64 = 0;
        __builtin_memcpy(&prefix64, &ip6h->daddr, sizeof(prefix64));
        return wan_intro_dispatch(ctx, prefix64);
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

    bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;
    u16 l2_proto = is_v6 ? ETH_IPV6 : ETH_IPV4;

    /* The session identifies the PPP link: a hit is one of our (native)
     * sessions and resolves the chain root directly. A miss is not one of
     * our sessions — today it still falls through to the inner-IP key and
     * the ingress-ifindex fallback (the transitional path all PPPoE
     * traffic takes while no sessions are registered); once native PPPoE
     * publishes its sessions, misses should be passed untouched instead. */
    u32 root = wan_trie_resolve(&wan_trie_tbl, wan_trie_key_ppp(pppoe->session_id));

    u8 mac_pair[12];
    __builtin_memcpy(mac_pair, eth->h_dest, sizeof(mac_pair));

    bool is_bcast = false;
    if (!root) {
        if (is_v6) {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(pppoe + 1);
            if ((void *)(ip6h + 1) > data_end) {
                return XDP_PASS;
            }

            if (unlikely(is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8))) {
                return XDP_PASS;
            }

            u64 prefix64 = 0;
            __builtin_memcpy(&prefix64, &ip6h->daddr, sizeof(prefix64));
            root = wan_trie_resolve(&wan_trie_tbl, prefix64);
        } else {
            struct iphdr *iph = (struct iphdr *)(pppoe + 1);
            if ((void *)(iph + 1) > data_end) {
                return XDP_PASS;
            }

            if (unlikely(is_broadcast_ip4(iph->daddr))) {
                return XDP_PASS;
            }

            root = wan_trie_resolve(&wan_trie_tbl, wan_trie_key_v4(iph->daddr));
        }
    } else {
        /* Our session: the inner IP is parsed only to keep broadcast and
         * multicast traffic out of the chain; those are passed up (headers
         * already stripped) for the stack to handle. */
        if (is_v6) {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)(pppoe + 1);
            if ((void *)(ip6h + 1) > data_end) {
                return XDP_PASS;
            }

            is_bcast = is_broadcast_ip6(ip6h->daddr.in6_u.u6_addr8);
        } else {
            struct iphdr *iph = (struct iphdr *)(pppoe + 1);
            if ((void *)(iph + 1) > data_end) {
                return XDP_PASS;
            }

            is_bcast = is_broadcast_ip4(iph->daddr);
        }
    }

    int result = bpf_xdp_adjust_head(ctx, 8);
    if (result != 0) {
        ld_bpf_log("bpf_xdp_adjust_head failed: %d", result);
        return XDP_DROP;
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end) {
        return XDP_DROP;
    }

    __builtin_memcpy(eth->h_dest, mac_pair, sizeof(mac_pair));
    eth->h_proto = l2_proto;

    /* Broadcast/multicast inner traffic of our own session: hand the
     * stripped (plain eth/IP) frame to the stack instead of the chain. */
    if (is_bcast) {
        return XDP_PASS;
    }

    if (root) {
        wan_intro_tailcall_root(ctx, root);
    }
    return XDP_PASS;

#undef BPF_LOG_TOPIC
}
