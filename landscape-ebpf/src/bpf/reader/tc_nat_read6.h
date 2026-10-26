// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_TC_NAT_READ6_H
#define LAND_TC_NAT_READ6_H

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"
#include "frag/tc_frag6.h"
#include "reader/tc_ip6_walk.h"
#include "tc_nat_view.h"

/*
 * NAT IPv6 reader: use the shared IPv6 walker for L3 navigation, then resolve
 * the transport tuple and the first-fragment cache. Addresses are written
 * through `src_addr`/`dst_addr`; everything else is packed into `view`.
 * ICMPv6 Echo stores its identifier in both sport and dport.
 */

static __always_inline int tc_nat_read6_icmp_error(struct __sk_buff *skb, struct tc_nat_view *view,
                                                   struct in6_addr *src_addr,
                                                   struct in6_addr *dst_addr, __u32 l3_offset,
                                                   __u32 l4_offset, __u32 packet_end) {
    struct icmp6_error_meta meta = {};
    if (!view || !src_addr || !dst_addr || l4_offset < l3_offset ||
        icmp6_parse_error(skb, l3_offset, l4_offset, packet_end, &meta) < 0)
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

static __always_inline int tc_nat_read6(struct __sk_buff *skb, struct tc_nat_view *view,
                                        struct in6_addr *src_addr, struct in6_addr *dst_addr,
                                        __u32 l3_offset, __u8 direction) {
    if (!view || !src_addr || !dst_addr) return 0;

    __u8 next = 0;
    __u8 frag = 0;
    __u8 frag_next = 0;
    __be32 frag_id = 0;
    __u32 packet_end = 0;
    int hlen = tc_ip6_hdrlen(skb, l3_offset, &next, &frag, &packet_end, &frag_id, &frag_next, 0, 0,
                             src_addr, dst_addr);
    if (hlen < 0) return 0;

    __u32 l4_offset = l3_offset + (__u32)hlen;

    view->l3_offset = (__u8)l3_offset;
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
        return 1;
    }

    __u32 payload = packet_end - l4_offset;
    view->l4_offset = (__u16)l4_offset;
    view->l4_protocol = next;

    __u32 pull_len;
    if (next == IPV6_NH_TCP)
        pull_len = l4_offset + sizeof(struct tcphdr);
    else if (next == IPV6_NH_UDP)
        pull_len = l4_offset + sizeof(struct udphdr);
    else if (next == IPV6_NH_ICMPV6)
        pull_len = l4_offset + sizeof(struct icmp6hdr);
    else
        return 1;

    if (pull_len > packet_end) pull_len = packet_end;
    if (pull_len > skb->len) pull_len = skb->len;
    if (bpf_skb_pull_data(skb, pull_len) != 0) return 0;
    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    int has_ports = 0;
    if (next == IPV6_NH_TCP) {
        if (payload < sizeof(struct tcphdr)) return 0;
        struct tcphdr *tcp = (struct tcphdr *)(data + l4_offset);
        if ((char *)(tcp + 1) > data_end) return 0;

        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return 0;

        view->sport = tcp->source;
        view->dport = tcp->dest;
        view->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        has_ports = 1;
    } else if (next == IPV6_NH_UDP) {
        if (payload < sizeof(struct udphdr)) return 0;
        struct udphdr *udp = (struct udphdr *)(data + l4_offset);
        if ((char *)(udp + 1) > data_end) return 0;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (frag != LAND_FRAG_FIRST && udp_len > payload)) return 0;

        view->sport = udp->source;
        view->dport = udp->dest;
        has_ports = 1;
    } else if (next == IPV6_NH_ICMPV6) {
        if (payload < sizeof(struct icmp6hdr)) return 0;
        struct icmp6hdr *icmp = (struct icmp6hdr *)(data + l4_offset);
        if ((char *)(icmp + 1) > data_end) return 0;

        if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST || icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
            view->sport = icmp->icmp6_dataun.u_echo.identifier;
            view->dport = view->sport;
            has_ports = 1;
        } else if (icmp->icmp6_type == ICMPV6_DEST_UNREACH ||
                   icmp->icmp6_type == ICMPV6_PKT_TOOBIG ||
                   icmp->icmp6_type == ICMPV6_TIME_EXCEED || icmp->icmp6_type == ICMPV6_PARAMPROB) {
            if (frag == LAND_FRAG_FIRST) return 0;
            if (tc_nat_read6_icmp_error(skb, view, src_addr, dst_addr, l3_offset, l4_offset,
                                        packet_end) < 0)
                return 0;
        }
    }

    if (has_ports) view->ports_valid = 1;

    if (frag == LAND_FRAG_FIRST && has_ports)
        frag6_cache_store(src_addr, dst_addr, frag_id, next, frag_next, view->sport, view->dport, 1,
                          direction);
    return 1;
}

#endif /* LAND_TC_NAT_READ6_H */
