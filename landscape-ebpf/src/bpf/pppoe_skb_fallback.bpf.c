#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"

/* Sessions owned by the native PPPoE links on THIS interface
 * (host-order session id -> owning link's chain id, observability only;
 * key has no ifindex because the instance is per-iface). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u32);
} pppoe_sessions SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/* SKB-mode PPPoE decap fallback for interfaces where native XDP is
 * unavailable: decaps frames of our sessions so the TC ingress intro
 * can dispatch them; everything else passes untouched. */
SEC("xdp")
int pppoe_skb_fallback(struct xdp_md *ctx) {
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

    u16 session = bpf_ntohs(pppoe->session_id);
    u32 *own = bpf_map_lookup_elem(&pppoe_sessions, &session);
    if (!own) {
        ld_from_wan_log("session %x is not ours; passing untouched", session);
        return XDP_PASS;
    }

    bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;
    u16 l2_proto = is_v6 ? ETH_IPV6 : ETH_IPV4;

    u8 mac_pair[12];
    __builtin_memcpy(mac_pair, eth->h_dest, sizeof(mac_pair));

    int result = bpf_xdp_adjust_head(ctx, 8);
    if (result != 0) {
        ld_from_wan_log("bpf_xdp_adjust_head failed: %d", result);
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
    return XDP_PASS;
}
