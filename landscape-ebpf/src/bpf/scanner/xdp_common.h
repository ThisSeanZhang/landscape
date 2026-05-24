#ifndef __LD_XDP_SCANNER_COMMON_H__
#define __LD_XDP_SCANNER_COMMON_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "../pkg_def.h"

enum xdp_scan_status {
    XDP_SCAN_OK = 0,
    XDP_SCAN_ERR = 2,
    XDP_SCAN_UNSPEC = -1,
};

enum xdp_l3_proto {
    XDP_L3_NONE = 0,
    XDP_L3_V4 = 4,
    XDP_L3_V6 = 6,
    XDP_L3_ERR = -1,
};

static __always_inline bool xdp_no_room(const void *needed, const void *limit) {
    return unlikely(needed > limit);
}

#define XDP_REVALIDATE(ctx, d, de, h, off, len)                                                    \
    ({                                                                                             \
        void *_d = (void *)(long)(ctx)->data;                                                      \
        void *_de = (void *)(long)(ctx)->data_end;                                                 \
        *(d) = _d;                                                                                 \
        *(de) = _de;                                                                               \
        void *_p = _d + (off);                                                                     \
        *(h) = xdp_no_room(_p + (len), _de) ? NULL : _p;                                           \
        *(h) != NULL ? 0 : -1;                                                                     \
    })

static __always_inline enum xdp_l3_proto xdp_classify_l3(struct xdp_md *ctx) {
    void *data, *data_end;
    struct ethhdr *eth;

    if (XDP_REVALIDATE(ctx, &data, &data_end, &eth, 0, sizeof(*eth))) return XDP_L3_ERR;

    switch (eth->h_proto) {
    case ETH_IPV4:
        return XDP_L3_V4;
    case ETH_IPV6:
        return XDP_L3_V6;
    default:
        return XDP_L3_NONE;
    }
}

#endif /* __LD_XDP_SCANNER_COMMON_H__ */
