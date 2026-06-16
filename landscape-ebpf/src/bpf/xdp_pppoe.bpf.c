#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "chain/xdp_stage.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 session_id = 0;

#define ETH_PPP bpf_htons(0x8864)
#define ETH_PPP_IP bpf_htons(0x0021)
#define ETH_PPP_IPV6 bpf_htons(0x0057)
#define ETH_IPV4 bpf_htons(0x0800)
#define ETH_IPV6 bpf_htons(0x86DD)

struct pppoe_header {
    u8 version_and_type;
    u8 code;
    u16 session_id;
    u16 length;
    u16 protocol;
} __attribute__((packed));

static __always_inline int xdp_pppoe_encap(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    bool is_v6 = (eth->h_proto == ETH_IPV6);
    if (!is_v6 && eth->h_proto != ETH_IPV4) return XDP_PASS;

    u16 ppp_proto = is_v6 ? ETH_PPP_IPV6 : ETH_PPP_IP;

    int ret = bpf_xdp_adjust_head(ctx, -8);
    if (ret) return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct pppoe_header) > data_end) return XDP_PASS;

    unsigned char macs[12];
    __builtin_memcpy(macs, data + 8, 12);
    __builtin_memcpy(data, macs, 12);

    u16 pkt_sz = (u16)(data_end - data - sizeof(struct ethhdr) - sizeof(struct pppoe_header));

    struct pppoe_header hdr = {
        .version_and_type = 0x11,
        .code = 0x00,
        .session_id = session_id,
        .length = bpf_htons(pkt_sz + 2),
        .protocol = ppp_proto,
    };
    __builtin_memcpy(data + sizeof(struct ethhdr), &hdr, sizeof(hdr));

    eth = data;
    eth->h_proto = ETH_PPP;

    return XDP_PASS;
}

SEC("xdp")
int xdp_pppoe_encap_lan(struct xdp_md *ctx) {
    int ret = xdp_pppoe_encap(ctx);
    if (ret != XDP_PASS) return ret;

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);

    return XDP_PASS;
}
