/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_XDP_NAT_READ4_H
#define LAND_XDP_NAT_READ4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "base/l4.h"
#include "base/tcp_phase.h"
#include "frag/frag.h"
#include "frag/tc_frag4.h"
#include "reader/xdp_ip4_walk.h"
#include "xdp_nat_view.h"

/*
 * XDP NAT IPv4 reader: use the shared XDP IPv4 walker for L3 navigation, then
 * resolve the transport tuple (including ICMP Error) and the first-fragment
 * cache. Addresses are written through src_addr/dst_addr; the rest is stored
 * in xdp_nat_view. ICMP Query stores its identifier in both sport and dport.
 */

#define XDP_NAT4_READ_DROP -1
#define XDP_NAT4_READ_PASS 0
#define XDP_NAT4_READ_OK 1

static __always_inline int xdp_icmp4_parse_error(void *data, void *data_end, __u32 l3_offset,
                                                 __u32 l4_offset, __u32 ip_total,
                                                 struct icmp4_error_meta *meta) {
    if (!meta || l4_offset < l3_offset || ip_total > ICMP_ERROR_MAX_TOTAL_LEN) return -1;

    __u32 ihl = l4_offset - l3_offset;
    if (ip_total < ihl) return -1;
    __u32 icmp_len = ip_total - ihl;
    if (icmp_len < ICMP_ERROR_HDR_LEN || icmp_len > ICMP_ERROR_MAX_TOTAL_LEN ||
        l4_offset > l3_offset + IPV4_HDR_MAX_LEN)
        return -1;

    __u32 pkt_len = (__u32)((char *)data_end - (char *)data);
    if (l4_offset > pkt_len || icmp_len > pkt_len - l4_offset) return -1;

    struct iphdr *outer = (struct iphdr *)((char *)data + l3_offset);
    if ((char *)(outer + 1) > (char *)data_end) return -1;
    if (ipv4_has_fragment(bpf_ntohs(outer->frag_off))) return -1;

    struct icmphdr *icmp = (struct icmphdr *)((char *)data + l4_offset);
    if ((char *)(icmp + 1) > (char *)data_end) return -1;
    if (icmp->type != ICMP_DEST_UNREACH && icmp->type != ICMP_TIME_EXCEEDED) return -1;

    struct iphdr *emb = (struct iphdr *)(icmp + 1);
    if ((char *)(emb + 1) > (char *)data_end || icmp_len < ICMP_ERROR_HDR_LEN + sizeof(*emb) ||
        emb->version != IPV4_VERSION)
        return -1;

    __u32 eihl = (__u32)emb->ihl * 4U;
    if (eihl < IPV4_HDR_MIN_LEN || eihl > IPV4_HDR_MAX_LEN ||
        ICMP_ERROR_HDR_LEN + eihl + 8U > icmp_len || (char *)emb + eihl > (char *)data_end)
        return -1;
    if (ipv4_has_fragment_offset(bpf_ntohs(emb->frag_off))) return -1;

    __u32 emb_total = bpf_ntohs(emb->tot_len);
    if (emb_total < eihl + 8U) return -1;

    void *el4 = (char *)emb + eihl;
    if ((char *)el4 + 8U > (char *)data_end) return -1;

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
            (char *)tcp + sizeof(*tcp) <= (char *)data_end)
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

static __always_inline int xdp_nat_read4(void *data, void *data_end, struct xdp_nat_view *view,
                                         __be32 *src_addr, __be32 *dst_addr, __u32 l3_offset,
                                         __u8 direction) {
    if (!view || !src_addr || !dst_addr) return XDP_NAT4_READ_DROP;

    __u8 next = 0;
    __u8 frag = 0;
    __be16 ip_id = 0;
    __u32 packet_end = 0;
    int ihl = xdp_ip4_hdrlen(data, data_end, l3_offset, &next, &frag, &packet_end, &ip_id, src_addr,
                             dst_addr);
    if (ihl < 0) return XDP_NAT4_READ_DROP;

    __u32 ip_total = packet_end - l3_offset;
    __u32 payload = ip_total - (__u32)ihl;
    __u32 l4_offset = l3_offset + (__u32)ihl;

    view->l4_offset = (__u16)l4_offset;
    view->l4_protocol = next;
    view->tcp_phase = NAPT_TCP_PHASE_NONE;
    view->sport = 0;
    view->dport = 0;
    view->ports_valid = 0;
    view->icmp_inner_l4_offset = 0;
    view->icmp_inner_l4_protocol = 0;
    view->frag_code = frag;

    if (frag >= LAND_NAT_FRAG_NON_INITIAL) {
        __be16 sport = 0;
        __be16 dport = 0;

        view->l4_offset = 0;
        if (frag4_cache_lookup(*src_addr, *dst_addr, ip_id, next, direction, &sport, &dport)) {
            view->sport = sport;
            view->dport = dport;
            view->ports_valid = 1;
        }
        /* A cache miss is decided by the NAT state: malformed/unknown
         * fragments never reach the transport parser. */
        return XDP_NAT4_READ_OK;
    }

    if (next != IPV4_PROTO_TCP && next != IPV4_PROTO_UDP && next != IPV4_PROTO_ICMP)
        return XDP_NAT4_READ_PASS;

    int first_fragment = frag == LAND_NAT_FRAG_FIRST;
    int cacheable = 0;

    if (next == IPV4_PROTO_TCP) {
        if (payload < sizeof(struct tcphdr)) return XDP_NAT4_READ_DROP;
        struct tcphdr *tcp = (struct tcphdr *)((char *)data + l4_offset);
        if ((char *)(tcp + 1) > (char *)data_end) return XDP_NAT4_READ_DROP;
        if (tcp_doff_bytes(tcp) < sizeof(*tcp)) return XDP_NAT4_READ_DROP;

        view->sport = tcp->source;
        view->dport = tcp->dest;
        view->tcp_phase = napt_tcp_phase_from_flags(tcp_hdr_flags(tcp));
        cacheable = 1;
    } else if (next == IPV4_PROTO_UDP) {
        if (payload < sizeof(struct udphdr)) return XDP_NAT4_READ_DROP;
        struct udphdr *udp = (struct udphdr *)((char *)data + l4_offset);
        if ((char *)(udp + 1) > (char *)data_end) return XDP_NAT4_READ_DROP;

        __u32 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(*udp) || (!first_fragment && udp_len > payload))
            return XDP_NAT4_READ_DROP;

        view->sport = udp->source;
        view->dport = udp->dest;
        cacheable = 1;
    } else {
        if (payload < sizeof(struct icmphdr)) return XDP_NAT4_READ_DROP;
        struct icmphdr *icmp = (struct icmphdr *)((char *)data + l4_offset);
        if ((char *)(icmp + 1) > (char *)data_end) return XDP_NAT4_READ_DROP;

        __u8 query_type = ICMP_ECHO_REPLY;
        if (direction == LAND_NAT_FRAG_FROM_LAN) query_type = ICMP_ECHO_REQUEST;

        if (icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_TIME_EXCEEDED) {
            struct icmp4_error_meta meta = {};
            if (xdp_icmp4_parse_error(data, data_end, l3_offset, l4_offset, ip_total, &meta) < 0)
                return XDP_NAT4_READ_DROP;

            *src_addr = meta.src_addr;
            *dst_addr = meta.dst_addr;
            view->sport = meta.src_port;
            view->dport = meta.dst_port;
            view->l4_protocol = meta.proto;
            view->tcp_phase = meta.tcp_phase;
            view->icmp_inner_l4_offset = (__u16)meta.inner_l4_offset;
            view->icmp_inner_l4_protocol = meta.proto;
            view->ports_valid = 1;
            return XDP_NAT4_READ_OK;
        }

        if (icmp->type != query_type || icmp->code != ICMP_ECHO_CODE) return XDP_NAT4_READ_DROP;

        view->sport = icmp->un.echo.id;
        view->dport = view->sport;
        cacheable = 1;
    }

    if (cacheable) view->ports_valid = 1;

    if (first_fragment && cacheable)
        frag4_cache_store(*src_addr, *dst_addr, ip_id, next, view->sport, view->dport, direction);

    return XDP_NAT4_READ_OK;
}

#endif /* LAND_XDP_NAT_READ4_H */
