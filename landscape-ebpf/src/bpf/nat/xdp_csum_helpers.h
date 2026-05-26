#ifndef __LD_XDP_CSUM_HELPERS_H__
#define __LD_XDP_CSUM_HELPERS_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* inline checksum helpers.
 *
 * Background: bpf_csum_diff returns a raw 32-bit __wsum delta.
 * To apply it to a 16-bit checksum field, use:
 *     csum_fold(csum_add(delta, ~csum_unfold(old_csum)))
 *
 * The Linux kernel's __csum_replace_by_diff does exactly this.
 *
 * On LE x86, __be16/__be32 values read from the packet are in HOST byte order.
 * bpf_csum_diff reads memory in native order; the entire chain is self-consistent.
 *
 * For __be16 values (ports, checksums), cast to __be32 before passing to
 * bpf_csum_diff to satisfy the 4-byte alignment requirement.
 */

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

/* Apply a 32-bit delta to a 16-bit checksum field.
 * Equivalent to Linux __csum_replace_by_diff.
 */
static __always_inline __sum16 xdp_csum_apply(__sum16 old, __wsum delta) {
    return xdp_csum_fold(xdp_csum_add(delta, ~xdp_csum_unfold(old)));
}

/* Compute addr delta (2 x __be32) and apply to checksum field in one step. */
static __always_inline __sum16 xdp_csum_update_addr(__be32 *old_addr, __be32 *new_addr,
                                                    __sum16 csum) {
    __wsum d = bpf_csum_diff(old_addr, 4, new_addr, 4, 0);
    return xdp_csum_apply(csum, d);
}

/* Compute port delta (padded __be32) and apply to checksum field. */
static __always_inline void xdp_csum_update_port_and_addr(__sum16 *csum, __be32 old_port32,
                                                          __be32 new_port32, __be32 old_addr,
                                                          __be32 new_addr) {
    __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
    __wsum da = bpf_csum_diff(&old_addr, 4, &new_addr, 4, 0);
    *csum = xdp_csum_apply(*csum, xdp_csum_add(dp, da));
}

#endif /* __LD_XDP_CSUM_HELPERS_H__ */
