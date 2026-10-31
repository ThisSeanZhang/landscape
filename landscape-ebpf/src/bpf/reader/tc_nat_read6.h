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

/*
 * NAT IPv6 reader: scan the packet once, write the final offsets into
 * `off`, and expose the address/ports as separate values. The NAT modify
 * path consumes those results directly; it never re-parses the packet.
 */

static __always_inline int
tc_nat_read6_icmp_error(struct __sk_buff *skb, __u32 l3_offset, __u32 l4_offset, __u32 packet_end,
                        struct ip6_scan_offsets *off, struct in6_addr *src_addr,
                        struct in6_addr *dst_addr, __be16 *sport, __be16 *dport) {
    struct icmp6_error_meta meta = {};
    if (icmp6_parse_error(skb, l3_offset, l4_offset, packet_end, &meta) < 0) return -1;

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
    return 0;
}

static __always_inline int tc_nat_read6(struct __sk_buff *skb, __u32 l3_offset, __u8 direction,
                                        struct ip6_scan_offsets *off, struct in6_addr *src_addr,
                                        struct in6_addr *dst_addr, __be16 *sport, __be16 *dport) {
    if (!off || !src_addr || !dst_addr || !sport || !dport ||
        (l3_offset != 0 && l3_offset != sizeof(struct ethhdr)))
        return 0;

    *sport = 0;
    *dport = 0;
    off->tcp_phase = NAPT_TCP_PHASE_NONE;
    off->ports_valid = 0;
    off->icmp_error_l3_offset = 0;
    off->icmp_inner_l4_offset = 0;
    off->icmp_inner_l4_protocol = 0;

    char *data = ip6_skb_data(skb);
    char *data_end = ip6_skb_data_end(skb);
    struct ipv6hdr *iph = (struct ipv6hdr *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) {
        if (bpf_skb_pull_data(skb, l3_offset + IPV6_HDR_LEN) != 0) return 0;
        data = ip6_skb_data(skb);
        data_end = ip6_skb_data_end(skb);
        iph = (struct ipv6hdr *)(data + l3_offset);
        if ((char *)(iph + 1) > data_end) return 0;
    }
    struct in6_addr src_tmp = iph->saddr;
    struct in6_addr dst_tmp = iph->daddr;

    __be32 frag_id = 0;
    __u8 frag_next = 0;
    __u32 packet_end = 0;
    if (ip6_scan_ext(skb, l3_offset, IP6_SCAN_MAX_EXT, off, &frag_id, &frag_next, &packet_end) < 0)
        return 0;
    if (packet_end > skb->len || off->l4_offset > packet_end) return 0;

    *src_addr = src_tmp;
    *dst_addr = dst_tmp;

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
        return 1;
    }

    __u32 l4_offset = off->l4_offset;
    __u32 payload = packet_end - l4_offset;
    __u8 next = off->l4_protocol;

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

    data = ip6_skb_data(skb);
    data_end = ip6_skb_data_end(skb);

    int has_ports = 0;
    if (next == IPV6_NH_TCP) {
        if (payload < sizeof(struct tcphdr)) return 0;
        struct tcphdr *tcp = (struct tcphdr *)(data + l4_offset);
        if ((char *)(tcp + 1) > data_end) return 0;

        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return 0;

        *sport = tcp->source;
        *dport = tcp->dest;
        off->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        has_ports = 1;
    } else if (next == IPV6_NH_UDP) {
        if (payload < sizeof(struct udphdr)) return 0;
        struct udphdr *udp = (struct udphdr *)(data + l4_offset);
        if ((char *)(udp + 1) > data_end) return 0;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (off->frag_code != LAND_FRAG_FIRST && udp_len > payload))
            return 0;

        *sport = udp->source;
        *dport = udp->dest;
        has_ports = 1;
    } else if (next == IPV6_NH_ICMPV6) {
        if (payload < sizeof(struct icmp6hdr)) return 0;
        struct icmp6hdr *icmp = (struct icmp6hdr *)(data + l4_offset);
        if ((char *)(icmp + 1) > data_end) return 0;

        if (icmp->icmp6_type == ICMPV6_ECHO_REQUEST || icmp->icmp6_type == ICMPV6_ECHO_REPLY) {
            *sport = icmp->icmp6_dataun.u_echo.identifier;
            *dport = *sport;
            has_ports = 1;
        } else if (icmp->icmp6_type == ICMPV6_DEST_UNREACH ||
                   icmp->icmp6_type == ICMPV6_PKT_TOOBIG ||
                   icmp->icmp6_type == ICMPV6_TIME_EXCEED || icmp->icmp6_type == ICMPV6_PARAMPROB) {
            if (off->frag_code == LAND_FRAG_FIRST) return 0;
            if (tc_nat_read6_icmp_error(skb, l3_offset, l4_offset, packet_end, off, src_addr,
                                        dst_addr, sport, dport) < 0)
                return 0;
        }
    }

    if (has_ports) off->ports_valid = 1;

    if (off->frag_code == LAND_FRAG_FIRST && has_ports)
        frag6_cache_store(src_addr, dst_addr, frag_id, next, frag_next, *sport, *dport, 1,
                          direction);
    return 1;
}

#endif /* LAND_TC_NAT_READ6_H */
