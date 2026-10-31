/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_XDP_NAT_READ6_H
#define LAND_XDP_NAT_READ6_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"
#include "frag/tc_frag6.h"

/*
 * XDP NAT IPv6 reader: scan the packet once, write the final offsets into
 * `off`, and expose the address/ports as separate values. The NAT modify
 * path consumes those results directly; it never re-parses the packet.
 */

#define XDP_NAT6_READ_DROP -1
#define XDP_NAT6_READ_PASS 0
#define XDP_NAT6_READ_OK 1

static __always_inline int xdp_icmp6_parse_error(struct xdp_md *ctx, __u32 l3_offset,
                                                 __u32 l4_offset, __u32 packet_end,
                                                 struct icmp6_error_meta *meta) {
    const char *data = (const char *)(long)ctx->data;
    const char *data_end = (const char *)(long)ctx->data_end;
    if (!meta || l4_offset < l3_offset || l4_offset > packet_end) return -1;
    if (l4_offset + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) > packet_end) return -1;
    if (packet_end - l4_offset > ICMP6_ERROR_MAX_TOTAL_LEN) return -1;

    __u32 pkt_len = (__u32)(data_end - data);
    if (packet_end > pkt_len) return -1;

    const struct ipv6hdr *outer = (const struct ipv6hdr *)(data + l3_offset);
    const struct icmp6hdr *icmp = (const struct icmp6hdr *)(data + l4_offset);
    if ((const void *)(outer + 1) > (const void *)data_end) return -1;
    if ((const void *)(icmp + 1) > (const void *)data_end) return -1;

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
    const struct ipv6hdr *emb = (const struct ipv6hdr *)(data + inner_l3_offset);
    if ((const void *)(emb + 1) > (const void *)data_end || emb->version != IPV6_VERSION) return -1;

    struct ip6_scan_offsets inner = {};
    __be32 inner_frag_id = 0;
    __u8 inner_frag_next = 0;
    __u32 inner_packet_end = 0;
    if (ip6_scan_ext_linear(data, data_end, inner_l3_offset, IP6_SCAN_MAX_EXT, &inner,
                            &inner_frag_id, &inner_frag_next, &inner_packet_end) < 0)
        return -1;

    if (inner.frag_code == LAND_FRAG_NON_INITIAL) return -1;
    if (inner.l4_offset > packet_end || inner.l4_offset + 8U > packet_end) return -1;
    if ((const void *)(data + inner.l4_offset) + 8U > (const void *)data_end) return -1;

    outer = (const struct ipv6hdr *)(data + l3_offset);
    emb = (const struct ipv6hdr *)(data + inner_l3_offset);
    if ((const void *)(outer + 1) > (const void *)data_end) return -1;
    if ((const void *)(emb + 1) > (const void *)data_end) return -1;

    meta->src_addr = emb->daddr;
    meta->dst_addr = outer->daddr;
    meta->inner_l3_offset = inner_l3_offset;
    meta->inner_l4_offset = inner.l4_offset;
    meta->proto = inner.l4_protocol;
    meta->tcp_phase = NAPT_TCP_PHASE_NONE;

    if (inner.l4_protocol == IPV6_NH_TCP || inner.l4_protocol == IPV6_NH_UDP) {
        const __be16 *ports = (const __be16 *)(data + inner.l4_offset);
        meta->src_port = ports[1];
        meta->dst_port = ports[0];
    } else if (inner.l4_protocol == IPV6_NH_ICMPV6) {
        const struct icmp6hdr *inner_icmp = (const struct icmp6hdr *)(data + inner.l4_offset);
        if ((const void *)(inner_icmp + 1) > (const void *)data_end) return -1;
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

static __always_inline int xdp_nat_read6(struct xdp_md *ctx, __u32 l3_offset, __u8 direction,
                                         struct ip6_scan_offsets *off, struct in6_addr *src_addr,
                                         struct in6_addr *dst_addr, __be16 *sport, __be16 *dport) {
    if (!off || !src_addr || !dst_addr || !sport || !dport ||
        (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return XDP_NAT6_READ_DROP;

    const char *data = (const char *)(long)ctx->data;
    const char *data_end = (const char *)(long)ctx->data_end;

    *sport = 0;
    *dport = 0;
    off->tcp_phase = NAPT_TCP_PHASE_NONE;
    off->ports_valid = 0;
    off->icmp_error_l3_offset = 0;
    off->icmp_inner_l4_offset = 0;
    off->icmp_inner_l4_protocol = 0;

    __be32 frag_id = 0;
    __u8 frag_next = 0;
    __u32 packet_end = 0;
    if (ip6_scan_ext_linear(data, data_end, l3_offset, IP6_SCAN_MAX_EXT, off, &frag_id, &frag_next,
                            &packet_end) < 0)
        return XDP_NAT6_READ_DROP;
    __u32 pkt_len = (__u32)(data_end - data);
    if (packet_end > pkt_len || off->l4_offset > packet_end) return XDP_NAT6_READ_DROP;

    const struct ipv6hdr *iph = (const struct ipv6hdr *)(data + l3_offset);
    if ((const void *)(iph + 1) > (const void *)data_end) return XDP_NAT6_READ_DROP;
    *src_addr = iph->saddr;
    *dst_addr = iph->daddr;

    if (off->frag_code == LAND_FRAG_NON_INITIAL) {
        struct frag6_cache_value value = {};

        off->l4_offset = 0;
        off->l4_protocol = frag_next;
        if (frag6_cache_lookup(src_addr, dst_addr, frag_id, frag_next, direction, &value)) {
            *sport = value.src_port;
            *dport = value.dst_port;
            off->ports_valid = (value.flags & NPTV6_FRAG_FLAG_HAS_PORTS) ? 1 : 0;
            off->l4_protocol = value.proto;
        }
        return XDP_NAT6_READ_OK;
    }

    __u32 l4_offset = off->l4_offset;
    __u32 payload = packet_end - l4_offset;
    __u8 next = off->l4_protocol;

    int has_ports = 0;
    if (next == IPV6_NH_TCP) {
        if (payload < sizeof(struct tcphdr)) return XDP_NAT6_READ_DROP;
        const struct tcphdr *tcp = (const struct tcphdr *)(data + l4_offset);
        if ((const void *)(tcp + 1) > (const void *)data_end) return XDP_NAT6_READ_DROP;
        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return XDP_NAT6_READ_DROP;

        *sport = tcp->source;
        *dport = tcp->dest;
        off->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        has_ports = 1;
    } else if (next == IPV6_NH_UDP) {
        if (payload < sizeof(struct udphdr)) return XDP_NAT6_READ_DROP;
        const struct udphdr *udp = (const struct udphdr *)(data + l4_offset);
        if ((const void *)(udp + 1) > (const void *)data_end) return XDP_NAT6_READ_DROP;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (off->frag_code != LAND_FRAG_FIRST && udp_len > payload))
            return XDP_NAT6_READ_DROP;

        *sport = udp->source;
        *dport = udp->dest;
        has_ports = 1;
    } else if (next == IPV6_NH_ICMPV6) {
        if (payload < sizeof(struct icmp6hdr)) return XDP_NAT6_READ_DROP;
        const struct icmp6hdr *icmp = (const struct icmp6hdr *)(data + l4_offset);
        if ((const void *)(icmp + 1) > (const void *)data_end) return XDP_NAT6_READ_DROP;

        if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST || icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
            *sport = icmp->icmp6_dataun.u_echo.identifier;
            *dport = *sport;
            has_ports = 1;
        } else if (icmp->icmp6_type == ICMPV6_DEST_UNREACH ||
                   icmp->icmp6_type == ICMPV6_PKT_TOOBIG ||
                   icmp->icmp6_type == ICMPV6_TIME_EXCEED || icmp->icmp6_type == ICMPV6_PARAMPROB) {
            if (off->frag_code == LAND_FRAG_FIRST) return XDP_NAT6_READ_DROP;

            struct icmp6_error_meta meta = {};
            if (xdp_icmp6_parse_error(ctx, l3_offset, l4_offset, packet_end, &meta) < 0)
                return XDP_NAT6_READ_DROP;

            *src_addr = meta.src_addr;
            *dst_addr = meta.dst_addr;
            *sport = meta.src_port;
            *dport = meta.dst_port;
            off->icmp_error_l3_offset = (__u16)meta.inner_l3_offset;
            off->icmp_inner_l4_offset = (__u16)meta.inner_l4_offset;
            off->icmp_inner_l4_protocol = meta.proto;
            off->l4_protocol = meta.proto;
            off->tcp_phase = meta.tcp_phase;
            off->ports_valid = 1;
            return XDP_NAT6_READ_OK;
        }
    } else {
        return XDP_NAT6_READ_PASS;
    }

    if (has_ports) off->ports_valid = 1;

    if (off->frag_code == LAND_FRAG_FIRST && has_ports)
        frag6_cache_store(src_addr, dst_addr, frag_id, next, frag_next, *sport, *dport, 1,
                          direction);
    return XDP_NAT6_READ_OK;
}

#endif /* LAND_XDP_NAT_READ6_H */
