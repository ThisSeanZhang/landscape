// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_IPV6_H
#define LAND_NAT_IPV6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"

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

#define IP6_SCAN_MAX_EXT 6U
#define IP6_SCAN_MAX_OFFSET 20480U

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

static __always_inline char *ip6_skb_data(const struct __sk_buff *skb) {
    u64 v;
    __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"
                         : "=r"(v)
                         : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, data)));
    return (char *)(long)v;
}

static __always_inline char *ip6_skb_data_end(const struct __sk_buff *skb) {
    u64 v;
    __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"
                         : "=r"(v)
                         : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, data_end)));
    return (char *)(long)v;
}

struct ip6_scan_offsets {
    __u8 l3_offset;
    __u16 l4_offset;
    __u8 l4_protocol;
    __u8 tcp_phase;
    __u8 ports_valid;

    __u16 icmp_error_l3_offset;
    __u16 icmp_inner_l4_offset;
    __u8 icmp_inner_l4_protocol;

    /* Reader/test observability; the NAT modify path does not consume it. */
    __u8 frag_code;
};

/*
 * Walk the IPv6 extension-header chain and write the final offsets directly
 * into `off`. The inner ICMPv6 error path uses this same walker, which keeps
 * both header walks in one small state machine. Returns 0 on success and
 * leaves packet_end at l3_offset + IPV6_HDR_LEN + payload_len.
 */
static __always_inline int ip6_scan_ext(struct __sk_buff *skb, __u32 l3_offset, __u32 max_ext,
                                        struct ip6_scan_offsets *off, __be32 *frag_id,
                                        __u8 *frag_next, __u32 *packet_end) {
    if (!off || max_ext == 0) return -1;

    char *data = ip6_skb_data(skb);
    char *data_end = ip6_skb_data_end(skb);

    if (l3_offset == sizeof(struct ethhdr)) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            if (bpf_skb_pull_data(skb, l3_offset) != 0) return -1;
            data = ip6_skb_data(skb);
            data_end = ip6_skb_data_end(skb);
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return -1;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return -1;
    }

    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        if (bpf_skb_pull_data(skb, l3_offset + IPV6_HDR_LEN) != 0) return -1;
        data = ip6_skb_data(skb);
        data_end = ip6_skb_data_end(skb);
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return -1;
    }
    if (iph->version != IPV6_VERSION) return -1;

    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if (payload_len == 0) return -1;
    if (packet_end) *packet_end = l3_offset + IPV6_HDR_LEN + payload_len;

    __u8 cur = iph->nexthdr;
    __u32 offset = l3_offset + IPV6_HDR_LEN;
    __u8 frag_code = LAND_FRAG_NONE;
    __be32 id = 0;
    __u8 frag_nh = 0;
    int seen_fragment = 0;

    for (__u32 i = 0; i < max_ext; i++) {
        if (cur == IPV6_NH_FRAGMENT) {
            if (seen_fragment) return -1;
            if (offset + sizeof(struct frag_hdr) > IP6_SCAN_MAX_OFFSET) return -1;

            struct frag_hdr *fh = (struct frag_hdr *)(data + offset);
            if ((char *)(fh + 1) > data_end) {
                if (bpf_skb_pull_data(skb, offset + sizeof(*fh)) != 0) return -1;
                data = ip6_skb_data(skb);
                data_end = ip6_skb_data_end(skb);
                fh = (struct frag_hdr *)(data + offset);
                if ((char *)(fh + 1) > data_end) return -1;
            }

            seen_fragment = 1;
            id = fh->identification;
            frag_nh = fh->nexthdr;
            __be16 frag_off = fh->frag_off;
            offset += sizeof(struct frag_hdr);
            cur = fh->nexthdr;

            if (ipv6_frag_offset(frag_off) != 0) {
                frag_code = LAND_FRAG_NON_INITIAL;
                goto done;
            }

            frag_code = ipv6_frag_more(frag_off) ? LAND_FRAG_FIRST : LAND_FRAG_SINGLE_V6H;
            continue;
        }

        if (cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING || cur == IPV6_NH_DSTOPTS) {
            if (offset + sizeof(struct ipv6_opt_hdr) > IP6_SCAN_MAX_OFFSET) return -1;

            struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr *)(data + offset);
            if ((char *)(ext + 1) > data_end) {
                if (bpf_skb_pull_data(skb, offset + sizeof(*ext)) != 0) return -1;
                data = ip6_skb_data(skb);
                data_end = ip6_skb_data_end(skb);
                ext = (struct ipv6_opt_hdr *)(data + offset);
                if ((char *)(ext + 1) > data_end) return -1;
            }

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > IP6_SCAN_MAX_OFFSET - offset)
                return -1;

            cur = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        goto done;
    }

    /* Exhausted the supported extension-header budget. */
    if (cur == IPV6_NH_FRAGMENT || cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING ||
        cur == IPV6_NH_DSTOPTS)
        return -1;

done:
    off->l3_offset = (__u8)l3_offset;
    off->l4_offset = (__u16)offset;
    off->l4_protocol = cur;
    off->frag_code = frag_code;
    if (frag_id) *frag_id = id;
    if (frag_next) *frag_next = frag_nh;
    return 0;
}

static __always_inline int ip6_scan_ext_linear(const char *data, const char *data_end,
                                               __u32 l3_offset, __u32 max_ext,
                                               struct ip6_scan_offsets *off, __be32 *frag_id,
                                               __u8 *frag_next, __u32 *packet_end) {
    if (!off || !data || !data_end || max_ext == 0) return -1;

    if (l3_offset == sizeof(struct ethhdr)) {
        const struct ethhdr *eth = (const struct ethhdr *)data;
        if ((const void *)(eth + 1) > (const void *)data_end) return -1;
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return -1;
    }

    const struct ipv6hdr *iph = (const struct ipv6hdr *)(data + l3_offset);
    if ((const void *)(iph + 1) > (const void *)data_end) return -1;
    if (iph->version != IPV6_VERSION) return -1;

    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if (payload_len == 0) return -1;
    if (packet_end) *packet_end = l3_offset + IPV6_HDR_LEN + payload_len;

    __u8 cur = iph->nexthdr;
    __u32 offset = l3_offset + IPV6_HDR_LEN;
    __u8 frag_code = LAND_FRAG_NONE;
    __be32 id = 0;
    __u8 frag_nh = 0;
    int seen_fragment = 0;

    for (__u32 i = 0; i < max_ext; i++) {
        if (cur == IPV6_NH_FRAGMENT) {
            if (seen_fragment) return -1;
            if (offset + sizeof(struct frag_hdr) > IP6_SCAN_MAX_OFFSET) return -1;

            const struct frag_hdr *fh = (const struct frag_hdr *)(data + offset);
            if ((const void *)(fh + 1) > (const void *)data_end) return -1;

            seen_fragment = 1;
            id = fh->identification;
            frag_nh = fh->nexthdr;
            __be16 frag_off = fh->frag_off;
            offset += sizeof(struct frag_hdr);
            cur = fh->nexthdr;

            if (ipv6_frag_offset(frag_off) != 0) {
                frag_code = LAND_FRAG_NON_INITIAL;
                goto done;
            }

            frag_code = ipv6_frag_more(frag_off) ? LAND_FRAG_FIRST : LAND_FRAG_SINGLE_V6H;
            continue;
        }

        if (cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING || cur == IPV6_NH_DSTOPTS) {
            if (offset + sizeof(struct ipv6_opt_hdr) > IP6_SCAN_MAX_OFFSET) return -1;

            const struct ipv6_opt_hdr *ext = (const struct ipv6_opt_hdr *)(data + offset);
            if ((const void *)(ext + 1) > (const void *)data_end) return -1;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > IP6_SCAN_MAX_OFFSET - offset)
                return -1;

            cur = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        goto done;
    }

    if (cur == IPV6_NH_FRAGMENT || cur == IPV6_NH_HOPOPTS || cur == IPV6_NH_ROUTING ||
        cur == IPV6_NH_DSTOPTS)
        return -1;

done:
    off->l3_offset = (__u8)l3_offset;
    off->l4_offset = (__u16)offset;
    off->l4_protocol = cur;
    off->frag_code = frag_code;
    if (frag_id) *frag_id = id;
    if (frag_next) *frag_next = frag_nh;
    return 0;
}

#define ICMP6_ERROR_MAX_TOTAL_LEN 1280U

struct icmp6_error_meta {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
    __u32 inner_l3_offset;
    __u32 inner_l4_offset;
    __u8 proto;
    __u8 tcp_phase;
};

static __always_inline int icmp6_parse_error(struct __sk_buff *skb, __u32 l3_offset,
                                             __u32 l4_offset, __u32 packet_end,
                                             struct icmp6_error_meta *meta) {
    if (!meta || l4_offset < l3_offset || l4_offset > packet_end) return -1;
    if (l4_offset + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) > packet_end) return -1;
    if (packet_end > skb->len || packet_end - l4_offset > ICMP6_ERROR_MAX_TOTAL_LEN) return -1;

    __u32 need = l4_offset + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr);
    if (bpf_skb_pull_data(skb, need) != 0) return -1;

    char *data = ip6_skb_data(skb);
    char *data_end = ip6_skb_data_end(skb);

    struct ipv6hdr *outer = (struct ipv6hdr *)(data + l3_offset);
    struct icmp6hdr *icmp = (struct icmp6hdr *)(data + l4_offset);
    if ((char *)(outer + 1) > data_end) return -1;
    if ((char *)(icmp + 1) > data_end) return -1;

    switch (icmp->icmp6_type) {
    case ICMPV6_DEST_UNREACH:
    case ICMPV6_PKT_TOOBIG:
    case ICMPV6_TIME_EXCEED:
    case ICMPV6_PARAMPROB:
        break;
    default:
        return -1;
    }

    __u32 inner_l3_offset = l4_offset + sizeof(struct icmp6hdr);
    struct ipv6hdr *emb = (struct ipv6hdr *)(data + inner_l3_offset);
    if ((char *)(emb + 1) > data_end || emb->version != IPV6_VERSION) return -1;

    struct ip6_scan_offsets inner = {};
    __be32 inner_frag_id = 0;
    __u8 inner_frag_next = 0;
    __u32 inner_packet_end = 0;
    if (ip6_scan_ext(skb, inner_l3_offset, IP6_SCAN_MAX_EXT, &inner, &inner_frag_id,
                     &inner_frag_next, &inner_packet_end) < 0)
        return -1;

    if (inner.frag_code == LAND_FRAG_NON_INITIAL) return -1;
    if (inner.l4_offset > packet_end || inner.l4_offset + 8U > packet_end) return -1;
    if (bpf_skb_pull_data(skb, inner.l4_offset + 8U) != 0) return -1;

    data = ip6_skb_data(skb);
    data_end = ip6_skb_data_end(skb);
    if ((char *)(data + inner.l4_offset) + 8U > data_end) return -1;

    outer = (struct ipv6hdr *)(data + l3_offset);
    emb = (struct ipv6hdr *)(data + inner_l3_offset);
    if ((char *)(outer + 1) > data_end || (char *)(emb + 1) > data_end) return -1;

    meta->src_addr = emb->daddr;
    meta->dst_addr = outer->daddr;
    meta->inner_l3_offset = inner_l3_offset;
    meta->inner_l4_offset = inner.l4_offset;
    meta->proto = inner.l4_protocol;
    meta->tcp_phase = NAPT_TCP_PHASE_NONE;

    if (inner.l4_protocol == IPV6_NH_TCP || inner.l4_protocol == IPV6_NH_UDP) {
        __be16 *ports = (__be16 *)(data + inner.l4_offset);
        meta->src_port = ports[1];
        meta->dst_port = ports[0];
    } else if (inner.l4_protocol == IPV6_NH_ICMPV6) {
        struct icmp6hdr *inner_icmp = (struct icmp6hdr *)(data + inner.l4_offset);
        if ((char *)(inner_icmp + 1) > data_end) return -1;
        if (inner_icmp->icmp6_type != ICMPV6_ECHO_REQUEST &&
            inner_icmp->icmp6_type != ICMPV6_ECHO_REPLY)
            return -1;
        meta->src_port = inner_icmp->icmp6_dataun.u_echo.identifier;
        meta->dst_port = meta->src_port;
    } else {
        return -1;
    }

    return 0;
}

#endif /* LAND_NAT_IPV6_H */
