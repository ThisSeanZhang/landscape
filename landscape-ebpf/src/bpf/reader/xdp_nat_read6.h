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
#include "reader/xdp_ip6_walk.h"
#include "xdp_nat_view.h"

/*
 * XDP NAT IPv6 reader: use the shared XDP IPv6 walker for L3 navigation, then
 * resolve the transport tuple (including ICMPv6 Error) and the IPv6 fragment
 * cache. Addresses are written through src_addr/dst_addr; the rest is stored
 * in xdp_nat_view. ICMPv6 Echo stores its identifier in both sport and dport.
 */

#define XDP_NAT6_READ_DROP -1
#define XDP_NAT6_READ_PASS 0
#define XDP_NAT6_READ_OK 1

static __always_inline int xdp_icmp6_parse_error(struct xdp_md *ctx, __u32 l3_offset,
                                                 __u32 l4_offset, __u32 packet_end,
                                                 struct icmp6_error_meta *meta) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (!meta || l4_offset < l3_offset || l4_offset > packet_end) return -1;
    if (l4_offset + sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr) > packet_end) return -1;
    if (packet_end - l4_offset > ICMP6_ERROR_MAX_TOTAL_LEN) return -1;

    __u32 pkt_len = (__u32)((char *)data_end - (char *)data);
    if (packet_end > pkt_len) return -1;

    struct ipv6hdr *outer = (struct ipv6hdr *)((char *)data + l3_offset);
    struct icmp6hdr *icmp = (struct icmp6hdr *)((char *)data + l4_offset);
    if ((char *)(outer + 1) > (char *)data_end) return -1;
    if ((char *)(icmp + 1) > (char *)data_end) return -1;

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
    if ((char *)(emb + 1) > (char *)data_end || emb->version != IPV6_VERSION) return -1;

    __u32 offset = l4_offset + sizeof(struct icmp6hdr) + IPV6_HDR_LEN;
    __u8 next = emb->nexthdr;

    for (__u32 i = 0; i < XDP_IP6_WALK_MAX_EXT; i++) {
        if (next == IPV6_NH_FRAGMENT) {
            if (offset + sizeof(struct frag_hdr) > packet_end) return -1;
            struct frag_hdr *frag = (struct frag_hdr *)((char *)data + offset);
            if ((char *)(frag + 1) > (char *)data_end) return -1;
            if (ipv6_frag_offset(frag->frag_off) != 0) return -1;

            next = frag->nexthdr;
            offset += sizeof(struct frag_hdr);
            continue;
        }

        if (next == IPV6_NH_HOPOPTS || next == IPV6_NH_ROUTING || next == IPV6_NH_DSTOPTS) {
            if (offset + sizeof(struct ipv6_opt_hdr) > packet_end) return -1;
            struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr *)((char *)data + offset);
            if ((char *)(ext + 1) > (char *)data_end) return -1;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > packet_end - offset) return -1;

            next = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        break;
    }

    if (offset > packet_end || offset + 8U > packet_end) return -1;
    if ((char *)(data + offset) + 8U > (char *)data_end) return -1;

    outer = (struct ipv6hdr *)((char *)data + l3_offset);
    emb = (struct ipv6hdr *)((char *)data + l4_offset + sizeof(struct icmp6hdr));
    if ((char *)(outer + 1) > (char *)data_end) return -1;
    if ((char *)(emb + 1) > (char *)data_end) return -1;

    meta->src_addr = emb->daddr;
    meta->dst_addr = outer->daddr;
    meta->inner_l4_offset = offset;
    meta->proto = next;
    meta->tcp_phase = NAPT_TCP_PHASE_NONE;

    if (next == IPV6_NH_TCP || next == IPV6_NH_UDP) {
        __be16 *ports = (__be16 *)((char *)data + offset);
        meta->src_port = ports[1];
        meta->dst_port = ports[0];
    } else if (next == IPV6_NH_ICMPV6) {
        struct icmp6hdr *inner_icmp = (struct icmp6hdr *)((char *)data + offset);
        if ((char *)(inner_icmp + 1) > (char *)data_end) return -1;
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

static __always_inline int xdp_nat_read6(struct xdp_md *ctx, struct xdp_nat_view *view,
                                         struct in6_addr *src_addr, struct in6_addr *dst_addr,
                                         __u32 l3_offset, __u8 direction) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (!view || !src_addr || !dst_addr) return XDP_NAT6_READ_DROP;

    __u8 next = 0;
    __u8 frag = 0;
    __u8 frag_next = 0;
    __be32 frag_id = 0;
    __u32 packet_end = 0;
    int hlen = xdp_ip6_hdrlen(data, data_end, l3_offset, &next, &frag, &packet_end, &frag_id,
                              &frag_next, src_addr, dst_addr);
    if (hlen < 0) return XDP_NAT6_READ_DROP;

    __u32 l4_offset = l3_offset + (__u32)hlen;

    view->l4_offset = 0;
    view->l4_protocol = 0;
    view->tcp_phase = NAPT_TCP_PHASE_NONE;
    view->sport = 0;
    view->dport = 0;
    view->ports_valid = 0;
    view->icmp_inner_l4_offset = 0;
    view->icmp_inner_l4_protocol = 0;
    view->frag_code = frag;

    if (frag == LAND_FRAG_NON_INITIAL) {
        struct frag6_cache_value value = {};
        view->l4_protocol = frag_next;
        if (frag6_cache_lookup(src_addr, dst_addr, frag_id, frag_next, direction, &value)) {
            view->sport = value.src_port;
            view->dport = value.dst_port;
            view->ports_valid = (value.flags & NPTV6_FRAG_FLAG_HAS_PORTS) ? 1 : 0;
            view->l4_protocol = value.proto;
        }
        return XDP_NAT6_READ_OK;
    }

    __u32 payload = packet_end - l4_offset;
    view->l4_offset = (__u16)l4_offset;
    view->l4_protocol = next;

    int has_ports = 0;
    if (next == IPV6_NH_TCP) {
        if (payload < sizeof(struct tcphdr)) return XDP_NAT6_READ_DROP;
        struct tcphdr *tcp = (struct tcphdr *)((char *)data + l4_offset);
        if ((char *)(tcp + 1) > (char *)data_end) return XDP_NAT6_READ_DROP;
        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return XDP_NAT6_READ_DROP;

        view->sport = tcp->source;
        view->dport = tcp->dest;
        view->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        has_ports = 1;
    } else if (next == IPV6_NH_UDP) {
        if (payload < sizeof(struct udphdr)) return XDP_NAT6_READ_DROP;
        struct udphdr *udp = (struct udphdr *)((char *)data + l4_offset);
        if ((char *)(udp + 1) > (char *)data_end) return XDP_NAT6_READ_DROP;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (frag != LAND_FRAG_FIRST && udp_len > payload))
            return XDP_NAT6_READ_DROP;

        view->sport = udp->source;
        view->dport = udp->dest;
        has_ports = 1;
    } else if (next == IPV6_NH_ICMPV6) {
        if (payload < sizeof(struct icmp6hdr)) return XDP_NAT6_READ_DROP;
        struct icmp6hdr *icmp = (struct icmp6hdr *)((char *)data + l4_offset);
        if ((char *)(icmp + 1) > (char *)data_end) return XDP_NAT6_READ_DROP;

        if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST || icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
            view->sport = icmp->icmp6_dataun.u_echo.identifier;
            view->dport = view->sport;
            has_ports = 1;
        } else if (icmp->icmp6_type == ICMPV6_DEST_UNREACH ||
                   icmp->icmp6_type == ICMPV6_PKT_TOOBIG ||
                   icmp->icmp6_type == ICMPV6_TIME_EXCEED || icmp->icmp6_type == ICMPV6_PARAMPROB) {
            if (frag == LAND_FRAG_FIRST) return XDP_NAT6_READ_DROP;

            struct icmp6_error_meta meta = {};
            if (xdp_icmp6_parse_error(ctx, l3_offset, l4_offset, packet_end, &meta) < 0)
                return XDP_NAT6_READ_DROP;

            *src_addr = meta.src_addr;
            *dst_addr = meta.dst_addr;
            view->sport = meta.src_port;
            view->dport = meta.dst_port;
            view->l4_protocol = meta.proto;
            view->tcp_phase = meta.tcp_phase;
            view->icmp_inner_l4_offset = (__u16)meta.inner_l4_offset;
            view->icmp_inner_l4_protocol = meta.proto;
            view->ports_valid = 1;
            return XDP_NAT6_READ_OK;
        }
    } else {
        return XDP_NAT6_READ_PASS;
    }

    if (has_ports) view->ports_valid = 1;

    if (frag == LAND_FRAG_FIRST && has_ports)
        frag6_cache_store(src_addr, dst_addr, frag_id, next, frag_next, view->sport, view->dport, 1,
                          direction);
    return XDP_NAT6_READ_OK;
}

#endif /* LAND_XDP_NAT_READ6_H */
