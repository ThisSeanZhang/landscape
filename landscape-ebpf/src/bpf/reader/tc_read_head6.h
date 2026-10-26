// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef LAND_NAT_TC_READ_HEAD6_H
#define LAND_NAT_TC_READ_HEAD6_H

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"
#include "frag/tc_frag6.h"
#include "tc_nat_view.h"

/*
 * IPv6 reader: one call walks the extension-header chain, resolves the
 * transport tuple, and applies the first-fragment cache. The addresses are
 * written through `src_addr`/`dst_addr`; everything else is packed into `view`.
 * The view's l4_offset includes the Ethernet header and points from
 * skb->data to the transport header. ICMPv6 Echo stores its identifier in
 * both sport and dport.
 */

/* Largest extension-header chain this parser accepts. */
#define NPTV6_MAX_EXT_HEADERS 8U

static __always_inline int tc_read_ipv6_icmp_error(struct __sk_buff *skb, struct tc_nat_view *view,
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

static __always_inline int tc_read_ipv6(struct __sk_buff *skb, struct tc_nat_view *view,
                                        struct in6_addr *src_addr, struct in6_addr *dst_addr,
                                        __u32 l3_offset, __u8 direction) {
    if (!view || !src_addr || !dst_addr || (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return 0;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;

    if (l3_offset != 0) {
        struct ethhdr *eth = (struct ethhdr *)data;
        if ((char *)(eth + 1) > data_end) {
            __u32 need = l3_offset + IPV6_HDR_LEN;
            if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            eth = (struct ethhdr *)data;
            if ((char *)(eth + 1) > data_end) return 0;
        }
        if (eth->h_proto != bpf_htons(ETH_P_IPV6)) return 0;
    }

    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        __u32 need = l3_offset + IPV6_HDR_LEN;
        if (need > skb->len || bpf_skb_pull_data(skb, need) != 0) return 0;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return 0;
    }

    if (iph->version != IPV6_VERSION) return 0;
    __u16 payload_len = bpf_ntohs(iph->payload_len);
    if (payload_len == 0) return 0;

    __u32 packet_end = l3_offset + IPV6_HDR_LEN + payload_len;
    if (packet_end > skb->len) return 0;

    *src_addr = iph->saddr;
    *dst_addr = iph->daddr;
    view->l3_offset = (__u8)l3_offset;
    view->l4_offset = 0;
    view->l4_protocol = 0;
    view->tcp_phase = NAPT_TCP_PHASE_NONE;
    view->sport = 0;
    view->dport = 0;
    view->ports_valid = 0;
    view->icmp_inner_l4_offset = 0;
    view->icmp_inner_l4_protocol = 0;
    view->frag_code = LAND_NAT_FRAG_NONE;

    __u8 next = iph->nexthdr;
    __be32 frag_id = 0;
    __u8 frag_next_header = 0;
    __u32 offset = l3_offset + IPV6_HDR_LEN;
    int seen_fragment = 0;

    if (next == IPV6_NH_TCP || next == IPV6_NH_UDP) goto parse_l4;

    for (__u32 i = 0; i < NPTV6_MAX_EXT_HEADERS; i++) {
        if (next == IPV6_NH_FRAGMENT) {
            if (seen_fragment) return 0;

            __u32 need = offset + sizeof(struct frag_hdr);
            if (need > packet_end) return 0;
            if ((char *)(data + offset) + sizeof(struct frag_hdr) > data_end) {
                if (bpf_skb_pull_data(skb, need) != 0) return 0;
                data = (char *)(long)skb->data;
                data_end = (char *)(long)skb->data_end;
            }

            struct frag_hdr *frag = (struct frag_hdr *)(data + offset);
            if ((char *)(frag + 1) > data_end) return 0;

            seen_fragment = 1;
            frag_id = frag->identification;
            frag_next_header = frag->nexthdr;
            __be16 frag_off = frag->frag_off;

            if (ipv6_frag_offset(frag_off) != 0) {
                view->frag_code = LAND_NAT_FRAG_NON_INITIAL;
                next = frag->nexthdr;
                offset += sizeof(struct frag_hdr);
                break;
            }

            view->frag_code =
                ipv6_frag_more(frag_off) ? LAND_NAT_FRAG_FIRST : LAND_NAT_FRAG_SINGLE_V6H;
            next = frag->nexthdr;
            offset += sizeof(struct frag_hdr);
            continue;
        }

        if (next == IPV6_NH_HOPOPTS || next == IPV6_NH_ROUTING || next == IPV6_NH_DSTOPTS) {
            __u32 need = offset + sizeof(struct ipv6_opt_hdr);
            if (need > packet_end) return 0;
            if ((char *)(data + offset) + sizeof(struct ipv6_opt_hdr) > data_end) {
                if (bpf_skb_pull_data(skb, need) != 0) return 0;
                data = (char *)(long)skb->data;
                data_end = (char *)(long)skb->data_end;
            }

            struct ipv6_opt_hdr *ext = (struct ipv6_opt_hdr *)(data + offset);
            if ((char *)(ext + 1) > data_end) return 0;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(struct ipv6_opt_hdr) || ext_len > packet_end - offset) return 0;

            next = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        break;
    }

    if (offset > packet_end || offset > 0xFFFFU) return 0;

    if (view->frag_code == LAND_NAT_FRAG_NON_INITIAL) {
        struct frag6_cache_value value = {};
        view->l4_offset = 0;
        view->l4_protocol = frag_next_header;
        if (frag6_cache_lookup(src_addr, dst_addr, frag_id, frag_next_header, direction, &value)) {
            view->sport = value.src_port;
            view->dport = value.dst_port;
            view->ports_valid = (value.flags & NPTV6_FRAG_FLAG_HAS_PORTS) ? 1 : 0;
            view->l4_protocol = value.proto;
        }
        return 1;
    }

parse_l4:
    __u32 l4_offset = offset;
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
    if ((char *)(data + pull_len) > data_end) {
        if (bpf_skb_pull_data(skb, pull_len) != 0) return 0;
        data = (char *)(long)skb->data;
        data_end = (char *)(long)skb->data_end;
    }

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
        if (udp_len < sizeof(*udp) || (view->frag_code != LAND_NAT_FRAG_FIRST && udp_len > payload))
            return 0;

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
            if (view->frag_code == LAND_NAT_FRAG_FIRST ||
                view->frag_code == LAND_NAT_FRAG_NON_INITIAL)
                return 0;
            if (tc_read_ipv6_icmp_error(skb, view, src_addr, dst_addr, l3_offset, l4_offset,
                                        packet_end) < 0)
                return 0;
        }
    }

    if (has_ports) view->ports_valid = 1;

    if (view->frag_code == LAND_NAT_FRAG_FIRST && has_ports)
        frag6_cache_store(src_addr, dst_addr, frag_id, next, frag_next_header, view->sport,
                          view->dport, 1, direction);
    return 1;
}

#endif /* LAND_NAT_TC_READ_HEAD6_H */
