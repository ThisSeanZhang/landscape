#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"

#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES bpf_htons(0x8864)
#endif

#define ETH_P_PPP_IPV4 bpf_htons(0x0021)
#define ETH_P_PPP_IPV6 bpf_htons(0x0057)

const volatile __be16 session_id = 0;

struct __attribute__((packed)) pppoe_header {
    u8 version_and_type;
    u8 code;
    __be16 session_id;
    __be16 length;
    __be16 protocol;
};

char LICENSE[] SEC("license") = "GPL";

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

    if (session_id != 0 && pppoe->session_id != session_id) {
        ld_bpf_log("session_id mismatch: %x, session_id: %x", pppoe->session_id, session_id);
        return XDP_PASS;
    }

    bool is_v6 = pppoe->protocol == ETH_P_PPP_IPV6;
    u16 l2_proto = is_v6 ? ETH_IPV6 : ETH_IPV4;

    u8 mac_pair[12];
    __builtin_memcpy(mac_pair, eth->h_dest, sizeof(mac_pair));

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
    return XDP_PASS;

#undef BPF_LOG_TOPIC
}
