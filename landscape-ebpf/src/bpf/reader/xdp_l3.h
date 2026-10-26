// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_XDP_L3_H
#define LAND_XDP_L3_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"

enum xdp_l3_proto {
    XDP_L3_NONE = 0,
    XDP_L3_V4 = 4,
    XDP_L3_V6 = 6,
    XDP_L3_ERR = -1,
};

static __always_inline enum xdp_l3_proto xdp_classify_l3(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_L3_ERR;

    switch (eth->h_proto) {
    case ETH_IPV4:
        return XDP_L3_V4;
    case ETH_IPV6:
        return XDP_L3_V6;
    default:
        return XDP_L3_NONE;
    }
}

#endif /* LAND_XDP_L3_H */
