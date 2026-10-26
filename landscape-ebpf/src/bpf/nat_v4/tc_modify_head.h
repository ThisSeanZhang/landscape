/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_MODIFY_HEAD_H
#define LAND_NAT_TC_MODIFY_HEAD_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/tc_act.h"
#include "base/ipv4.h"
#include "base/l4.h"
#include "frag/frag.h"

/*
 * Fragment modify: there is no L4 header, so only the IPv4 addresses change.
 * The state phase has not touched the packet, so the original addresses and
 * checksum are still in the IPv4 header. `direction` selects which side gets
 * `new_addr`.
 */
static __always_inline int napt_modify_fragment(struct __sk_buff *skb, __be32 new_addr,
                                                __u8 direction, __u32 l3_offset) {
    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct iphdr *iph = (void *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) return TC_ACT_SHOT;

    __be32 old_src = iph->saddr;
    __be32 old_dst = iph->daddr;
    __u16 check = bpf_ntohs(iph->check);
    if (direction == LAND_FRAG_FROM_LAN) {
        if (new_addr == old_src) return TC_ACT_OK;
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_src, (const __u8 *)&new_addr);
        iph->saddr = new_addr;
    } else {
        if (new_addr == old_dst) return TC_ACT_OK;
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_dst, (const __u8 *)&new_addr);
        iph->daddr = new_addr;
    }
    iph->check = bpf_htons(check);
    return TC_ACT_OK;
}

/*
 * Common L4 modify stage. It needs only the skb, the translated side's address
 * and port, and the direction. The IPv4 protocol, IHL, total length, original
 * addresses, and checksum are read from the still-unmodified header.
 */
static __always_inline int napt_modify(struct __sk_buff *skb, __be32 new_addr, __be16 new_port,
                                       __u8 direction, __u32 l3_offset) {
    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct iphdr *iph = (void *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) return TC_ACT_SHOT;

    __u32 ihl = ((__u32)iph->ihl * 4U);
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN) return TC_ACT_SHOT;
    __u32 ip_total = bpf_ntohs(iph->tot_len);
    __u8 proto = iph->protocol;
    if (proto != IPV4_PROTO_UDP && proto != IPV4_PROTO_TCP && proto != IPV4_PROTO_ICMP)
        return TC_ACT_SHOT;
    __u32 l4_off = l3_offset + ihl;
    __u32 l4_min = sizeof(struct udphdr);
    if (proto == IPV4_PROTO_TCP)
        l4_min = sizeof(struct tcphdr);
    else if (proto == IPV4_PROTO_ICMP)
        l4_min = sizeof(struct icmphdr);
    if (ip_total < ihl + l4_min || data + l4_off + l4_min > data_end) return TC_ACT_SHOT;

    int lan = direction == LAND_FRAG_FROM_LAN;
    __be32 old_src = iph->saddr;
    __be32 old_dst = iph->daddr;
    __be32 new_src = lan ? new_addr : old_src;
    __be32 new_dst = lan ? old_dst : new_addr;
    __u16 check = bpf_ntohs(iph->check);
    if (new_src != old_src)
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_src, (const __u8 *)&new_src);
    if (new_dst != old_dst)
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_dst, (const __u8 *)&new_dst);
    iph->check = bpf_htons(check);
    iph->saddr = new_src;
    iph->daddr = new_dst;
    if (proto == IPV4_PROTO_ICMP) {
        struct icmphdr *icmp = (void *)(data + l4_off);
        __be16 old_id = icmp->un.echo.id;

        icmp->un.echo.id = new_port;
        /* RFC 792: the ICMP checksum has no pseudo-header. */
        bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct icmphdr, checksum), old_id,
                            new_port, 2);
        return TC_ACT_OK;
    }

    if (proto == IPV4_PROTO_TCP) {
        struct tcphdr *tcp = (void *)(data + l4_off);
        __be32 old_ip = lan ? old_src : old_dst;
        __be16 old_port = lan ? tcp->source : tcp->dest;
        __be32 new_ip = lan ? new_src : new_dst;

        if (lan)
            tcp->source = new_port;
        else
            tcp->dest = new_port;
        bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct tcphdr, check), old_ip, new_ip,
                            BPF_F_PSEUDO_HDR | 4);
        bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct tcphdr, check), old_port,
                            new_port, 2);
        return TC_ACT_OK;
    }

    struct udphdr *udp = (void *)(data + l4_off);
    __be32 old_ip = lan ? old_src : old_dst;
    __be16 old_port = lan ? udp->source : udp->dest;
    __sum16 old_check = udp->check;
    __be32 new_ip = lan ? new_src : new_dst;

    if (lan)
        udp->source = new_port;
    else
        udp->dest = new_port;
    if (old_check != 0) {
        bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct udphdr, check), old_ip, new_ip,
                            BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4);
        bpf_l4_csum_replace(skb, l4_off + __builtin_offsetof(struct udphdr, check), old_port,
                            new_port, BPF_F_MARK_MANGLED_0 | 2);
    }
    return TC_ACT_OK;
}

/*
 * RFC 5508 §4.2 and ADR 0013: translate an ICMP Error from either realm.
 * `from_wan` selects the external-realm path; the packet direction is the
 * realm containing the Error originator. The common read-only state phase has
 * already validated the embedded flow and produced `new_addr` / `new_port`;
 * this function must not refresh, delete, or otherwise touch state.
 */
static __always_inline void napt_emit_outer_ipv4(struct iphdr *iph, __be32 new_addr, int from_wan) {
    __be32 old_addr = from_wan ? iph->daddr : iph->saddr;
    if (new_addr == old_addr) return;

    __u16 check = bpf_ntohs(iph->check);
    check = ipv4_csum_replace_addr(check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
    iph->check = bpf_htons(check);
    if (from_wan)
        iph->daddr = new_addr;
    else
        iph->saddr = new_addr;
}

static __always_inline int napt_modify_icmp_error(struct __sk_buff *skb, __be32 new_addr,
                                                  __be16 new_port, int from_wan, __u32 l3_offset) {
    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    struct iphdr *iph = (void *)(data + l3_offset);
    if ((char *)(iph + 1) > data_end) return TC_ACT_SHOT;

    __u32 ihl = ((__u32)iph->ihl * 4U);
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN) return TC_ACT_SHOT;
    if (ipv4_has_fragment(bpf_ntohs(iph->frag_off))) return TC_ACT_SHOT;

    __u32 ip_total = bpf_ntohs(iph->tot_len);
    if (ip_total < ihl + ICMP_ERROR_HDR_LEN || ip_total > ICMP_ERROR_MAX_TOTAL_LEN)
        return TC_ACT_SHOT;
    __u32 l4_off = l3_offset + ihl;
    struct icmphdr *icmp = (void *)(data + l4_off);
    __u32 icmp_len = ip_total - ihl;
    if ((char *)icmp + ICMP_ERROR_HDR_LEN > (char *)data_end) return TC_ACT_SHOT;
    if (icmp->type != ICMP_DEST_UNREACH && icmp->type != ICMP_TIME_EXCEEDED) return TC_ACT_SHOT;

    struct iphdr *emb = (void *)(icmp + 1);
    if (icmp_len < ICMP_ERROR_HDR_LEN + sizeof(*emb) ||
        (char *)emb + sizeof(*emb) > (char *)data_end)
        return TC_ACT_SHOT;
    if (emb->version != IPV4_VERSION) return TC_ACT_SHOT;

    __u32 eihl = ((__u32)emb->ihl * 4U);
    if (eihl < IPV4_HDR_MIN_LEN || eihl > IPV4_HDR_MAX_LEN ||
        ICMP_ERROR_HDR_LEN + eihl + 8U > icmp_len || (char *)emb + eihl > (char *)data_end)
        return TC_ACT_SHOT;
    if (ipv4_has_fragment(bpf_ntohs(emb->frag_off))) return TC_ACT_SHOT;

    __u32 emb_total = bpf_ntohs(emb->tot_len);
    if (emb_total < eihl + 8U) return TC_ACT_SHOT;
    void *el4 = (char *)emb + eihl;
    if ((char *)el4 + 8U > (char *)data_end) return TC_ACT_SHOT;

    __u8 proto = emb->protocol;

    if (proto == IPV4_PROTO_UDP) {
        struct udphdr *udp = el4;
        __be32 old_addr = from_wan ? emb->saddr : emb->daddr;
        __be16 old_port = from_wan ? udp->source : udp->dest;

        __u16 old_ip_check = bpf_ntohs(emb->check);
        __u16 new_ip_check =
            ipv4_csum_replace_addr(old_ip_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        /* RFC5508-4.1-S3: never validate the embedded transport checksum. */
        __u16 old_udp_check = bpf_ntohs(udp->check);
        __u16 new_udp_check = old_udp_check;
        int update_udp_check = old_udp_check != 0;
        if (update_udp_check) {
            new_udp_check = ipv4_csum_replace_addr(old_udp_check, (const __u8 *)&old_addr,
                                                   (const __u8 *)&new_addr);
            new_udp_check = csum_replace16(new_udp_check, bpf_ntohs(old_port), bpf_ntohs(new_port));
            /* RFC 768: a computed zero is written as all ones. */
            if (new_udp_check == 0) new_udp_check = 0xffffU;
        }

        __u16 outer_check = bpf_ntohs(icmp->checksum);
        outer_check =
            ipv4_csum_replace_addr(outer_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        outer_check = csum_replace16(outer_check, old_ip_check, new_ip_check);
        outer_check = csum_replace16(outer_check, bpf_ntohs(old_port), bpf_ntohs(new_port));
        if (update_udp_check)
            outer_check = csum_replace16(outer_check, old_udp_check, new_udp_check);

        if (from_wan)
            emb->saddr = new_addr;
        else
            emb->daddr = new_addr;
        if (from_wan)
            udp->source = new_port;
        else
            udp->dest = new_port;
        emb->check = bpf_htons(new_ip_check);
        if (update_udp_check) udp->check = bpf_htons(new_udp_check);
        icmp->checksum = bpf_htons(outer_check);

        napt_emit_outer_ipv4(iph, new_addr, from_wan);
        return TC_ACT_OK;
    }

    if (proto == IPV4_PROTO_TCP) {
        struct tcphdr *tcp = el4;
        __be32 old_addr = from_wan ? emb->saddr : emb->daddr;
        __be16 old_port = from_wan ? tcp->source : tcp->dest;

        int tcp_checksum_present = emb_total >= eihl + sizeof(struct tcphdr) &&
                                   ICMP_ERROR_HDR_LEN + eihl + sizeof(struct tcphdr) <= icmp_len &&
                                   (char *)el4 + sizeof(struct tcphdr) <= (char *)data_end;
        __u16 old_ip_check = bpf_ntohs(emb->check);
        __u16 new_ip_check =
            ipv4_csum_replace_addr(old_ip_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        __u16 old_tcp_check = tcp_checksum_present ? bpf_ntohs(tcp->check) : 0;
        __u16 new_tcp_check = old_tcp_check;
        if (tcp_checksum_present) {
            new_tcp_check = ipv4_csum_replace_addr(old_tcp_check, (const __u8 *)&old_addr,
                                                   (const __u8 *)&new_addr);
            new_tcp_check = csum_replace16(new_tcp_check, bpf_ntohs(old_port), bpf_ntohs(new_port));
        }

        __u16 outer_check = bpf_ntohs(icmp->checksum);
        outer_check =
            ipv4_csum_replace_addr(outer_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        outer_check = csum_replace16(outer_check, old_ip_check, new_ip_check);
        outer_check = csum_replace16(outer_check, bpf_ntohs(old_port), bpf_ntohs(new_port));
        if (tcp_checksum_present)
            outer_check = csum_replace16(outer_check, old_tcp_check, new_tcp_check);

        if (from_wan)
            emb->saddr = new_addr;
        else
            emb->daddr = new_addr;
        if (from_wan)
            tcp->source = new_port;
        else
            tcp->dest = new_port;
        emb->check = bpf_htons(new_ip_check);
        if (tcp_checksum_present) tcp->check = bpf_htons(new_tcp_check);
        icmp->checksum = bpf_htons(outer_check);

        napt_emit_outer_ipv4(iph, new_addr, from_wan);
        return TC_ACT_OK;
    }

    if (proto == IPV4_PROTO_ICMP) {
        struct icmphdr *eicmp = el4;
        if (eicmp->code != ICMP_ECHO_CODE ||
            (eicmp->type != ICMP_ECHO_REQUEST && eicmp->type != ICMP_ECHO_REPLY))
            return TC_ACT_SHOT;

        __be32 old_addr = from_wan ? emb->saddr : emb->daddr;
        __be16 old_id = eicmp->un.echo.id;
        __be16 new_id = new_port;

        __u16 old_ip_check = bpf_ntohs(emb->check);
        __u16 new_ip_check =
            ipv4_csum_replace_addr(old_ip_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        __u16 old_icmp_check = bpf_ntohs(eicmp->checksum);
        __u16 new_icmp_check = csum_replace16(old_icmp_check, bpf_ntohs(old_id), bpf_ntohs(new_id));

        __u16 outer_check = bpf_ntohs(icmp->checksum);
        outer_check =
            ipv4_csum_replace_addr(outer_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        outer_check = csum_replace16(outer_check, old_ip_check, new_ip_check);
        outer_check = csum_replace16(outer_check, bpf_ntohs(old_id), bpf_ntohs(new_id));
        outer_check = csum_replace16(outer_check, old_icmp_check, new_icmp_check);

        if (from_wan)
            emb->saddr = new_addr;
        else
            emb->daddr = new_addr;
        eicmp->un.echo.id = new_id;
        emb->check = bpf_htons(new_ip_check);
        eicmp->checksum = bpf_htons(new_icmp_check);
        icmp->checksum = bpf_htons(outer_check);

        napt_emit_outer_ipv4(iph, new_addr, from_wan);
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

#endif /* LAND_NAT_TC_MODIFY_HEAD_H */
