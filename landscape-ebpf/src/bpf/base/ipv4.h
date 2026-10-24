/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_IPV4_H
#define LAND_NAT_IPV4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/l4.h"
#include "base/tcp_phase.h"

/*
 * IPv4 wire format and field masks.
 *
 * Source: RFC 791 §3.1 (header format, version, IHL, flags, fragment offset,
 * protocol). Protocol numbers: IANA "Assigned Internet Protocol Numbers".
 */

#define IPV4_VERSION 4U

/* IHL counts 32-bit words: minimum 5 (20 bytes), maximum 15 (60 bytes). */
#define IPV4_IHL_MIN 5U
#define IPV4_IHL_MAX 15U
#define IPV4_HDR_MIN_LEN 20U
#define IPV4_HDR_MAX_LEN 60U

/* Fragment offset field: 3 flag bits, then a 13-bit offset. RFC 791 §3.1. */
#define IPV4_FLAG_RESERVED 0x8000U
#define IPV4_FLAG_DF 0x4000U
#define IPV4_FLAG_MF 0x2000U
#define IPV4_FRAG_OFFSET_MASK 0x1fffU

/* IANA "Assigned Internet Protocol Numbers"; field defined in RFC 791 §3.1. */
#define IPV4_PROTO_ICMP 1U
#define IPV4_PROTO_TCP 6U
#define IPV4_PROTO_UDP 17U

/* RFC 894 Ethernet encapsulation; vmlinux.h exposes the header, not this tag. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800U
#endif

/*
 * RFC 791 §3.1: incremental IPv4 header checksum update for a changed 32-bit
 * address. The checksum covers the header in 16-bit words; changing one word
 * from old to new updates the one's-complement sum without recomputing the
 * whole header. `old_check` and the return value are host-order 16-bit words;
 * the caller converts them to and from the network-order header field.
 */
static inline __u16 ipv4_csum_replace_addr(__u16 old_check, const __u8 old_addr[4],
                                           const __u8 new_addr[4]) {
    /* Read wire bytes directly so this does not depend on host byte order. */
    __u16 old_hi = ((__u16)old_addr[0] << 8) | old_addr[1];
    __u16 old_lo = ((__u16)old_addr[2] << 8) | old_addr[3];
    __u16 new_hi = ((__u16)new_addr[0] << 8) | new_addr[1];
    __u16 new_lo = ((__u16)new_addr[2] << 8) | new_addr[3];

    /* S = ~checksum; S' = S - old + new in one's-complement arithmetic. */
    __u32 sum = (__u16)~old_check;
    sum += (__u16)~old_hi;
    sum += new_hi;
    sum += (__u16)~old_lo;
    sum += new_lo;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

/*
 * Caller must pass the fragment offset in host byte order, for example
 * bpf_ntohs(iph->frag_off). A packet is a fragment when MF is set or the
 * 13-bit offset is non-zero; DF alone does not make it a fragment.
 */
static inline int ipv4_has_fragment(__u16 frag_off_host) {
    return (frag_off_host & (IPV4_FLAG_MF | IPV4_FRAG_OFFSET_MASK)) != 0U;
}

/*
 * RFC 791 §3.1: a non-initial fragment has a non-zero 13-bit offset and no
 * transport header. The first fragment has offset zero even when MF is set.
 */
static inline int ipv4_has_fragment_offset(__u16 frag_off_host) {
    return (frag_off_host & IPV4_FRAG_OFFSET_MASK) != 0U;
}

/*
 * RFC 791 §3.1: update a one's-complement checksum for one
 * changed 16-bit word. Values are host-order 16-bit words. This is used for
 * the embedded transport checksum and the outer ICMP checksum, both of which
 * cover fields changed by ICMP Error translation.
 */
static inline __u16 csum_replace16(__u16 old_check, __u16 old_value, __u16 new_value) {
    __u32 sum = (__u16)~old_check;
    sum += (__u16)~old_value;
    sum += new_value;
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return (__u16)~sum;
}

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0U
#endif
#ifndef ICMP_ECHO_REQUEST
#define ICMP_ECHO_REQUEST 8U
#endif
#ifndef ICMP_ECHO_CODE
#define ICMP_ECHO_CODE 0U
#endif
#ifndef ICMP_ECHO_HDR_LEN
#define ICMP_ECHO_HDR_LEN 8U
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3U
#endif
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11U
#endif
#ifndef ICMP_ERROR_HDR_LEN
#define ICMP_ERROR_HDR_LEN 8U
#endif
#ifndef ICMP_ERROR_MAX_TOTAL_LEN
#define ICMP_ERROR_MAX_TOTAL_LEN 576U
#endif

_Static_assert(sizeof(struct icmphdr) == ICMP_ECHO_HDR_LEN, "ICMP header must be exactly 8 bytes");
_Static_assert(sizeof(struct icmphdr) == ICMP_ERROR_HDR_LEN,
               "ICMP Error header must be exactly 8 bytes");

struct icmp4_error_meta {
    __be32 src_addr;
    __be32 dst_addr;
    __be16 src_port;
    __be16 dst_port;
    __u32 inner_l4_offset;
    __u8 proto;
    __u8 tcp_phase;
};

static __always_inline int icmp4_parse_error(struct __sk_buff *skb, __u32 l3_offset,
                                             __u32 l4_offset, __u32 ip_total,
                                             struct icmp4_error_meta *meta) {
    if (!meta || l4_offset < l3_offset || ip_total > ICMP_ERROR_MAX_TOTAL_LEN) return -1;

    __u32 ihl = l4_offset - l3_offset;
    if (ip_total < ihl) return -1;
    __u32 icmp_len = ip_total - ihl;
    if (icmp_len < ICMP_ERROR_HDR_LEN) return -1;
    if (icmp_len > ICMP_ERROR_MAX_TOTAL_LEN || l4_offset > l3_offset + IPV4_HDR_MAX_LEN) return -1;

    __u32 full_len = l4_offset + icmp_len;
    if (full_len > skb->len) return -1;

    __u32 pull_len = ICMP_ERROR_HDR_LEN + IPV4_HDR_MAX_LEN + sizeof(struct tcphdr);
    if (pull_len > icmp_len) pull_len = icmp_len;
    __u32 pull_need = l4_offset + pull_len;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct icmphdr *icmp = (struct icmphdr *)(data + l4_offset);
    if ((char *)icmp + pull_len > data_end) {
        if (bpf_skb_pull_data(skb, pull_need) != 0) return -1;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        icmp = (struct icmphdr *)(data + l4_offset);
        if ((char *)icmp + pull_len > data_end) return -1;
    }

    struct iphdr *iph = (struct iphdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) return -1;
    if (ipv4_has_fragment(bpf_ntohs(iph->frag_off))) return -1;

    if ((char *)(icmp + 1) > data_end) return -1;
    if (icmp->type != ICMP_DEST_UNREACH && icmp->type != ICMP_TIME_EXCEEDED) return -1;

    struct iphdr *emb = (struct iphdr *)(icmp + 1);
    if ((char *)emb + sizeof(*emb) > data_end || icmp_len < ICMP_ERROR_HDR_LEN + sizeof(*emb) ||
        emb->version != IPV4_VERSION)
        return -1;

    __u32 eihl = (__u32)emb->ihl * 4U;
    if (eihl < IPV4_HDR_MIN_LEN || eihl > IPV4_HDR_MAX_LEN ||
        ICMP_ERROR_HDR_LEN + eihl + 8U > icmp_len || (char *)emb + eihl > data_end)
        return -1;
    if (ipv4_has_fragment_offset(bpf_ntohs(emb->frag_off))) return -1;

    __u32 emb_total = bpf_ntohs(emb->tot_len);
    if (emb_total < eihl + 8U) return -1;
    void *el4 = (char *)emb + eihl;
    if ((char *)el4 + 8U > data_end) return -1;

    __u8 proto = emb->protocol;
    meta->tcp_phase = NAPT_TCP_PHASE_NONE;
    meta->inner_l4_offset = l4_offset + ICMP_ERROR_HDR_LEN + eihl;
    meta->src_addr = emb->daddr;
    meta->dst_addr = emb->saddr;
    meta->proto = proto;

    if (proto == IPV4_PROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)el4;
        meta->src_port = udp->dest;
        meta->dst_port = udp->source;
    } else if (proto == IPV4_PROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)el4;
        meta->src_port = tcp->dest;
        meta->dst_port = tcp->source;
        if (emb_total >= eihl + sizeof(*tcp) &&
            ICMP_ERROR_HDR_LEN + eihl + sizeof(*tcp) <= icmp_len &&
            (char *)tcp + sizeof(*tcp) <= data_end)
            meta->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
    } else if (proto == IPV4_PROTO_ICMP) {
        struct icmphdr *eicmp = (struct icmphdr *)el4;
        if (eicmp->code != ICMP_ECHO_CODE ||
            (eicmp->type != ICMP_ECHO_REQUEST && eicmp->type != ICMP_ECHO_REPLY))
            return -1;
        meta->src_port = eicmp->un.echo.id;
        meta->dst_port = 0;
    } else {
        return -1;
    }

    return 0;
}

#endif /* LAND_NAT_IPV4_H */
