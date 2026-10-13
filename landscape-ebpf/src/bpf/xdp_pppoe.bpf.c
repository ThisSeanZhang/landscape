#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"
#include "chain/xdp_stage.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u16 session_id = 0;

static __always_inline int xdp_pppoe_encap(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    bool is_v6 = (eth->h_proto == ETH_IPV6);
    if (!is_v6 && eth->h_proto != ETH_IPV4) return XDP_PASS;

    u16 ppp_proto = is_v6 ? ETH_P_PPP_IPV6 : ETH_P_PPP_IPV4;

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
    eth->h_proto = ETH_P_PPP_SES;

    return XDP_PASS;
}

SEC("xdp")
int xdp_pppoe_encap_lan(struct xdp_md *ctx) {
    int ret = xdp_pppoe_encap(ctx);
    if (ret != XDP_PASS) return ret;

    XDP_FROM_LAN_CHAIN_NEXT(ctx);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);

    return XDP_PASS;
}
