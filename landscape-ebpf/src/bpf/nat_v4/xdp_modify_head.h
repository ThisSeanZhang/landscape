/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_XDP_MODIFY_HEAD_V4_H
#define LAND_NAT_XDP_MODIFY_HEAD_V4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "base/l4.h"
#include "frag/frag.h"
#include "nat_v4/xdp_csum.h"

/*
 * XDP counterpart of nat_v4/tc_modify_head.h.
 *
 * The IPv4 header and quoted ICMP Error checksums use the same incremental
 * helpers as the TC path. XDP has no bpf_l4_csum_replace(), so live transport
 * checksums use the xdp_csum helpers on the same field deltas.
 */

static __always_inline int napt_xdp_modify_fragment(void *data, void *data_end, __be32 new_addr,
                                                    __u8 direction, __u32 l3_offset) {
    struct iphdr *iph = (struct iphdr *)((char *)data + l3_offset);
    if ((char *)(iph + 1) > (char *)data_end) return -1;

    __be32 old_src = iph->saddr;
    __be32 old_dst = iph->daddr;
    __u16 check = bpf_ntohs(iph->check);
    if (direction == LAND_FRAG_FROM_LAN) {
        if (new_addr == old_src) return 0;
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_src, (const __u8 *)&new_addr);
        iph->saddr = new_addr;
    } else {
        if (new_addr == old_dst) return 0;
        check = ipv4_csum_replace_addr(check, (const __u8 *)&old_dst, (const __u8 *)&new_addr);
        iph->daddr = new_addr;
    }
    iph->check = bpf_htons(check);
    return 0;
}

static __always_inline int napt_xdp_modify(void *data, void *data_end, __be32 new_addr,
                                           __be16 new_port, __u8 direction, __u32 l3_offset) {
    struct iphdr *iph = (struct iphdr *)((char *)data + l3_offset);
    if ((char *)(iph + 1) > (char *)data_end) return -1;

    __u32 ihl = (__u32)iph->ihl * 4U;
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN) return -1;
    __u32 ip_total = bpf_ntohs(iph->tot_len);
    __u8 proto = iph->protocol;
    if (proto != IPV4_PROTO_UDP && proto != IPV4_PROTO_TCP && proto != IPV4_PROTO_ICMP) return -1;
    __u32 l4_off = l3_offset + ihl;
    __u32 l4_min = sizeof(struct udphdr);
    if (proto == IPV4_PROTO_TCP)
        l4_min = sizeof(struct tcphdr);
    else if (proto == IPV4_PROTO_ICMP)
        l4_min = sizeof(struct icmphdr);
    if (ip_total < ihl + l4_min || (char *)data + l4_off + l4_min > (char *)data_end) return -1;

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
        struct icmphdr *icmp = (struct icmphdr *)((char *)data + l4_off);
        if ((char *)(icmp + 1) > (char *)data_end) return -1;
        __be16 old_id = icmp->un.echo.id;
        __be32 old_id32 = (__be32)old_id;
        __be32 new_id32 = (__be32)new_port;
        __wsum delta = bpf_csum_diff(&old_id32, 4, &new_id32, 4, 0);

        icmp->un.echo.id = new_port;
        icmp->checksum = xdp_csum_apply(icmp->checksum, delta);
        return 0;
    }

    if (proto == IPV4_PROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)((char *)data + l4_off);
        if ((char *)(tcp + 1) > (char *)data_end) return -1;
        __be32 old_ip = lan ? old_src : old_dst;
        __be16 old_port = lan ? tcp->source : tcp->dest;
        __be32 new_ip = lan ? new_src : new_dst;
        __be32 old_port32 = (__be32)old_port;
        __be32 new_port32 = (__be32)new_port;
        __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
        __wsum da = bpf_csum_diff(&old_ip, 4, &new_ip, 4, 0);

        if (lan)
            tcp->source = new_port;
        else
            tcp->dest = new_port;
        tcp->check = xdp_csum_apply(tcp->check, xdp_csum_add(dp, da));
        return 0;
    }

    struct udphdr *udp = (struct udphdr *)((char *)data + l4_off);
    if ((char *)(udp + 1) > (char *)data_end) return -1;
    __be32 old_ip = lan ? old_src : old_dst;
    __be16 old_port = lan ? udp->source : udp->dest;
    __sum16 old_check = udp->check;
    __be32 new_ip = lan ? new_src : new_dst;
    __be32 old_port32 = (__be32)old_port;
    __be32 new_port32 = (__be32)new_port;
    __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
    __wsum da = bpf_csum_diff(&old_ip, 4, &new_ip, 4, 0);

    if (lan)
        udp->source = new_port;
    else
        udp->dest = new_port;
    if (old_check != 0) udp->check = xdp_csum_apply_udp4(old_check, xdp_csum_add(dp, da));
    return 0;
}

static __always_inline void napt_xdp_emit_outer_ipv4(struct iphdr *iph, __be32 new_addr,
                                                     int from_wan) {
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

static __always_inline int napt_xdp_modify_icmp_error(void *data, void *data_end, __be32 new_addr,
                                                      __be16 new_port, int from_wan,
                                                      __u32 l3_offset) {
    struct iphdr *iph = (struct iphdr *)((char *)data + l3_offset);
    if ((char *)(iph + 1) > (char *)data_end) return -1;

    __u32 ihl = (__u32)iph->ihl * 4U;
    if (ihl < IPV4_HDR_MIN_LEN || ihl > IPV4_HDR_MAX_LEN) return -1;
    if (ipv4_has_fragment(bpf_ntohs(iph->frag_off))) return -1;

    __u32 ip_total = bpf_ntohs(iph->tot_len);
    if (ip_total < ihl + ICMP_ERROR_HDR_LEN || ip_total > ICMP_ERROR_MAX_TOTAL_LEN) return -1;
    __u32 l4_off = l3_offset + ihl;
    struct icmphdr *icmp = (struct icmphdr *)((char *)data + l4_off);
    __u32 icmp_len = ip_total - ihl;
    if ((char *)icmp + ICMP_ERROR_HDR_LEN > (char *)data_end) return -1;
    if (icmp->type != ICMP_DEST_UNREACH && icmp->type != ICMP_TIME_EXCEEDED) return -1;

    struct iphdr *emb = (struct iphdr *)(icmp + 1);
    if (icmp_len < ICMP_ERROR_HDR_LEN + sizeof(*emb) ||
        (char *)emb + sizeof(*emb) > (char *)data_end)
        return -1;
    if (emb->version != IPV4_VERSION) return -1;

    __u32 eihl = (__u32)emb->ihl * 4U;
    if (eihl < IPV4_HDR_MIN_LEN || eihl > IPV4_HDR_MAX_LEN ||
        ICMP_ERROR_HDR_LEN + eihl + 8U > icmp_len || (char *)emb + eihl > (char *)data_end)
        return -1;
    if (ipv4_has_fragment(bpf_ntohs(emb->frag_off))) return -1;

    __u32 emb_total = bpf_ntohs(emb->tot_len);
    if (emb_total < eihl + 8U) return -1;
    void *el4 = (char *)emb + eihl;
    if ((char *)el4 + 8U > (char *)data_end) return -1;

    __u8 proto = emb->protocol;

    if (proto == IPV4_PROTO_UDP) {
        struct udphdr *udp = el4;
        __be32 old_addr = from_wan ? emb->saddr : emb->daddr;
        __be16 old_port = from_wan ? udp->source : udp->dest;

        __u16 old_ip_check = bpf_ntohs(emb->check);
        __u16 new_ip_check =
            ipv4_csum_replace_addr(old_ip_check, (const __u8 *)&old_addr, (const __u8 *)&new_addr);
        __u16 old_udp_check = bpf_ntohs(udp->check);
        __u16 new_udp_check = old_udp_check;
        int update_udp_check = old_udp_check != 0;
        if (update_udp_check) {
            new_udp_check = ipv4_csum_replace_addr(old_udp_check, (const __u8 *)&old_addr,
                                                   (const __u8 *)&new_addr);
            new_udp_check = csum_replace16(new_udp_check, bpf_ntohs(old_port), bpf_ntohs(new_port));
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

        napt_xdp_emit_outer_ipv4(iph, new_addr, from_wan);
        return 0;
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

        napt_xdp_emit_outer_ipv4(iph, new_addr, from_wan);
        return 0;
    }

    if (proto == IPV4_PROTO_ICMP) {
        struct icmphdr *eicmp = el4;
        if (eicmp->code != ICMP_ECHO_CODE ||
            (eicmp->type != ICMP_ECHO_REQUEST && eicmp->type != ICMP_ECHO_REPLY))
            return -1;

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

        napt_xdp_emit_outer_ipv4(iph, new_addr, from_wan);
        return 0;
    }

    return -1;
}

#endif /* LAND_NAT_XDP_MODIFY_HEAD_V4_H */
