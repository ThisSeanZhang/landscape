// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_IPV6_H
#define LAND_NAT_IPV6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/l4.h"
#include "base/tcp_phase.h"

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

#define ICMP6_ERROR_MAX_TOTAL_LEN 1280U

struct icmp6_error_meta {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    __be16 src_port;
    __be16 dst_port;
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

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

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

    struct ipv6hdr *emb = (struct ipv6hdr *)(icmp + 1);
    if ((char *)(emb + 1) > data_end || emb->version != IPV6_VERSION) return -1;

    __u32 offset = l4_offset + sizeof(struct icmp6hdr) + IPV6_HDR_LEN;
    __u8 next = emb->nexthdr;

    for (__u32 i = 0; i < 8U; i++) {
        if (next == IPV6_NH_FRAGMENT) {
            need = offset + sizeof(struct frag_hdr);
            if (need > packet_end || bpf_skb_pull_data(skb, need) != 0) return -1;

            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            struct frag_hdr *frag = (struct frag_hdr *)(data + offset);
            if ((char *)(frag + 1) > data_end) return -1;
            if (ipv6_frag_offset(frag->frag_off) != 0) return -1;

            next = frag->nexthdr;
            offset += sizeof(struct frag_hdr);
            continue;
        }

        if (next == IPV6_NH_HOPOPTS || next == IPV6_NH_ROUTING || next == IPV6_NH_DSTOPTS) {
            need = offset + sizeof(struct ipv6_opt_hdr);
            if (need > packet_end || bpf_skb_pull_data(skb, need) != 0) return -1;

            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr *)(data + offset);
            if ((char *)(ext + 1) > data_end) return -1;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > packet_end - offset) return -1;

            next = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        break;
    }

    if (offset > packet_end || offset + 8U > packet_end) return -1;
    need = offset + 8U;
    if (bpf_skb_pull_data(skb, need) != 0) return -1;

    data = (char *)(long)skb->data;
    data_end = (char *)(long)skb->data_end;
    if ((char *)(data + offset) + 8U > data_end) return -1;

    outer = (struct ipv6hdr *)(data + l3_offset);
    emb = (struct ipv6hdr *)(data + l4_offset + sizeof(struct icmp6hdr));
    if ((char *)(outer + 1) > data_end || (char *)(emb + 1) > data_end) return -1;

    meta->src_addr = emb->daddr;
    meta->dst_addr = outer->daddr;
    meta->inner_l4_offset = offset;
    meta->proto = next;
    meta->tcp_phase = NAPT_TCP_PHASE_NONE;

    if (next == IPV6_NH_TCP || next == IPV6_NH_UDP) {
        __be16 *ports = (__be16 *)(data + offset);
        meta->src_port = ports[1];
        meta->dst_port = ports[0];
    } else if (next == IPV6_NH_ICMPV6) {
        struct icmp6hdr *inner_icmp = (struct icmp6hdr *)(data + offset);
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
