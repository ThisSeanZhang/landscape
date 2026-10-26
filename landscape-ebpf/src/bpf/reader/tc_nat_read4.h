// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_NAT_READ4_H
#define LAND_TC_NAT_READ4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"
#include "frag/tc_frag4.h"
#include "reader/tc_ip4_walk.h"
#include "tc_nat_view.h"

/*
 * NAT IPv4 reader: use the shared IPv4 walker for L3 navigation, then resolve
 * the transport tuple (including ICMP Error) and the first-fragment cache.
 * Addresses are written through `src_addr`/`dst_addr`; everything else is
 * packed into `view`. Direction is a property of the TC path.
 */
/*
 * TCP phase is derived once from the TCP flags. The NAT state phase decides
 * which phases may create or refresh a connection-tracking entry.
 */

/*
 * Hard local bound for one linearization request. ICMP Error uses the 576-byte
 * outer-datagram bound; UDP, TCP, and ICMP Echo need only their L4 headers.
 */
#define NAPT_MAX_PULL 576U

static __always_inline int tc_nat_read4_icmp_error(struct __sk_buff *skb, struct tc_nat_view *view,
                                                   __be32 *src_addr, __be32 *dst_addr,
                                                   __u32 l3_offset, __u32 l4_offset,
                                                   __u32 ip_total) {
    struct icmp4_error_meta meta = {};
    if (!view || !src_addr || !dst_addr || l4_offset < l3_offset ||
        icmp4_parse_error(skb, l3_offset, l4_offset, ip_total, &meta) < 0)
        return -1;

    *src_addr = meta.src_addr;
    *dst_addr = meta.dst_addr;
    view->sport = meta.src_port;
    view->dport = meta.dst_port;
    view->l4_protocol = meta.proto;
    view->tcp_phase = meta.tcp_phase;
    view->icmp_inner_l4_offset = (__u16)meta.inner_l4_offset;
    view->icmp_inner_l4_protocol = meta.proto;
    view->ports_valid = 1;
    return 0;
}

static __always_inline int tc_nat_read4(struct __sk_buff *skb, struct tc_nat_view *view,
                                        __be32 *src_addr, __be32 *dst_addr, __u32 l3_offset,
                                        __u8 direction) {
    if (!view || !src_addr || !dst_addr) return 0;

    __u8 next = 0;
    __u8 frag = 0;
    __be16 ip_id = 0;
    __u32 packet_end = 0;
    int ihl =
        tc_ip4_hdrlen(skb, l3_offset, &next, &frag, &packet_end, &ip_id, 0, 0, src_addr, dst_addr);
    if (ihl < 0) return 0;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    __u32 ip_total = packet_end - l3_offset;
    __u32 payload = ip_total - (__u32)ihl;
    __u32 l4_offset = l3_offset + (__u32)ihl;

    view->l3_offset = (__u8)l3_offset;
    view->l4_offset = (__u16)l4_offset;
    view->l4_protocol = next;
    view->tcp_phase = NAPT_TCP_PHASE_NONE;
    view->sport = 0;
    view->dport = 0;
    view->ports_valid = 0;
    view->icmp_inner_l4_offset = 0;
    view->icmp_inner_l4_protocol = 0;
    view->frag_code = frag;

    if (frag >= LAND_FRAG_NON_INITIAL) {
        __be16 sport = 0;
        __be16 dport = 0;
        view->l4_offset = 0;
        if (frag4_cache_lookup(*src_addr, *dst_addr, ip_id, next, direction, &sport, &dport)) {
            view->sport = sport;
            view->dport = dport;
            view->ports_valid = 1;
        }
        return 1;
    }

    __u32 pull_len;
    if (next == IPV4_PROTO_TCP)
        pull_len = l4_offset + sizeof(struct tcphdr);
    else if (next == IPV4_PROTO_UDP)
        pull_len = l4_offset + sizeof(struct udphdr);
    else if (next == IPV4_PROTO_ICMP)
        pull_len = l4_offset + sizeof(struct icmphdr);
    else
        return 1;

    if (pull_len > packet_end) pull_len = packet_end;
    if (pull_len > skb->len) pull_len = skb->len;
    if (bpf_skb_pull_data(skb, pull_len) != 0) return 0;
    data = (char *)(long)skb->data;
    data_end = (char *)(long)skb->data_end;

    int cacheable = 0;
    int first_fragment = frag == LAND_FRAG_FIRST;
    if (next == IPV4_PROTO_UDP) {
        if (payload < sizeof(struct udphdr)) return 0;
        struct udphdr *udp = (struct udphdr *)(data + l4_offset);
        if ((char *)(udp + 1) > data_end) return 0;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (!first_fragment && udp_len > payload)) return 0;

        view->sport = udp->source;
        view->dport = udp->dest;
        cacheable = 1;
    } else if (next == IPV4_PROTO_TCP) {
        if (payload < sizeof(struct tcphdr)) return 0;
        struct tcphdr *tcp = (struct tcphdr *)(data + l4_offset);
        if ((char *)(tcp + 1) > data_end) return 0;

        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return 0;

        view->sport = tcp->source;
        view->dport = tcp->dest;
        view->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        cacheable = 1;
    } else if (next == IPV4_PROTO_ICMP) {
        if (payload < sizeof(struct icmphdr)) return 0;
        struct icmphdr *icmp = (struct icmphdr *)(data + l4_offset);
        if ((char *)(icmp + 1) > data_end) return 0;

        __u8 query_type = ICMP_ECHO_REPLY;
        if (direction == LAND_FRAG_FROM_LAN) query_type = ICMP_ECHO_REQUEST;
        if (icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_TIME_EXCEEDED) {
            if (tc_nat_read4_icmp_error(skb, view, src_addr, dst_addr, l3_offset, l4_offset,
                                        ip_total) < 0)
                return 0;
        } else if (icmp->type == query_type && icmp->code == ICMP_ECHO_CODE) {
            view->sport = icmp->un.echo.id;
            view->dport = view->sport;
            cacheable = 1;
        } else {
            return 0;
        }
    } else {
        return 1;
    }

    if (cacheable) view->ports_valid = 1;

    if (first_fragment && cacheable)
        frag4_cache_store(*src_addr, *dst_addr, ip_id, next, view->sport, view->dport, direction);
    return 1;
}

#endif /* LAND_TC_NAT_READ4_H */
