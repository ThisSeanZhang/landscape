/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __LD_NAT_V4_XDP_CSUM_H__
#define __LD_NAT_V4_XDP_CSUM_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

static __always_inline __wsum xdp_csum_add(__wsum csum, __wsum addend) {
    csum += addend;
    return csum + (csum < addend);
}

static __always_inline __sum16 xdp_csum_fold(__wsum csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__sum16)~csum;
}

static __always_inline __wsum xdp_csum_unfold(__sum16 csum) { return (__wsum)csum; }

/* Apply a 32-bit delta to a 16-bit checksum field. */
static __always_inline __sum16 xdp_csum_apply(__sum16 old, __wsum delta) {
    return xdp_csum_fold(xdp_csum_add(delta, ~xdp_csum_unfold(old)));
}

/* IPv4 UDP uses zero to mean "checksum disabled". */
static __always_inline __sum16 xdp_csum_apply_udp4(__sum16 old, __wsum delta) {
    if (old == 0) return 0;

    __sum16 csum = xdp_csum_apply(old, delta);
    return csum == 0 ? (__sum16)0xffff : csum;
}

#endif /* __LD_NAT_V4_XDP_CSUM_H__ */
