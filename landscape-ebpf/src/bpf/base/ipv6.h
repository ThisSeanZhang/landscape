// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_IPV6_H
#define LAND_NAT_IPV6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

/*
 * IPv6 wire format and the NPTv6 checksum-neutral arithmetic.
 *
 * Source: RFC 8200 §2-§4 for the fixed header and extension-header encoding;
 * RFC 6296 §2.6 and §3.1-§3.4 for the /48 adjustment; RFC 4291 for the
 * 64-bit prefix/subnet/IID split; RFC 1071 and RFC 1624 for one's-complement
 * checksum arithmetic.
 */

#define IPV6_VERSION 6U
#define IPV6_HDR_LEN 40U

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DDU
#endif

/* IANA "IPv6 Extension Header Types" and "Assigned Internet Protocol Numbers". */
#define IPV6_NH_HOPOPTS 0U
#define IPV6_NH_TCP 6U
#define IPV6_NH_UDP 17U
#define IPV6_NH_ROUTING 43U
#define IPV6_NH_FRAGMENT 44U
#define IPV6_NH_ESP 50U
#define IPV6_NH_AH 51U
#define IPV6_NH_ICMPV6 58U
#define IPV6_NH_NONE 59U
#define IPV6_NH_DSTOPTS 60U

#define IPV6_FRAG_OFFSET_MASK 0xfff8U
#define IPV6_FRAG_MORE 0x0001U

#define NPTV6_PREFIX_LEN 48U
#define NPTV6_PREFIX_BYTES 6U

/* RFC 8200 §4.5: 13-bit offset is in 8-octet units relative to the
 * Fragmentable Part; the low bit is M and bits 1-2 are reserved. */
static inline __u32 ipv6_frag_offset(__be16 frag_off) {
    return (__u32)(bpf_ntohs(frag_off) & IPV6_FRAG_OFFSET_MASK) >> 3;
}

static inline int ipv6_frag_more(__be16 frag_off) {
    return (bpf_ntohs(frag_off) & IPV6_FRAG_MORE) != 0;
}

/* RFC 8200 §4.3/§4.4/§4.6: length in 8-octet units, excluding the first 8. */
static inline __u32 ipv6_opt_len(const struct ipv6_opt_hdr *ext) {
    return ((__u32)ext->hdrlen + 1U) * 8U;
}

#endif /* LAND_NAT_IPV6_H */
