#ifndef __LD_SKB_SCANNER6_H__
#define __LD_SKB_SCANNER6_H__

#include "skb_common.h"

static __always_inline enum land_scan_result scan_ipv6(struct __sk_buff *skb,
                                                       struct ip_scanner_ctx *scanner_ctx) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, scanner_ctx->l4_offset, sizeof(*ip6h))) {
        return LD_SCAN_ERR;
    }

    if (ip6h->version != 6) {
        return LD_SCAN_ERR;
    }

    int payload_relative_pos = sizeof(struct ipv6hdr) + scanner_ctx->l4_offset;
    u32 frag_hdr_off = 0;
    u8 nexthdr = ip6h->nexthdr;

    struct ipv6_opt_hdr *opthdr;
    struct frag_hdr *frag_hdr;

    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_AUTH:
            return LD_SCAN_UNSPEC;
        case NEXTHDR_FRAGMENT: {
            if (VALIDATE_READ_DATA(skb, &frag_hdr, payload_relative_pos, sizeof(*frag_hdr))) {
                return LD_SCAN_ERR;
            }
            frag_hdr_off = payload_relative_pos;
            nexthdr = frag_hdr->nexthdr;
            payload_relative_pos += sizeof(*frag_hdr);
            break;
        }
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            if (VALIDATE_READ_DATA(skb, &opthdr, payload_relative_pos, sizeof(*opthdr))) {
                return LD_SCAN_ERR;
            }
            payload_relative_pos += (opthdr->hdrlen + 1) * 8;
            nexthdr = opthdr->nexthdr;
            break;
        }
        default:
            goto found_upper_layer;
        }
    }

    switch (nexthdr) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
    case NEXTHDR_ICMP:
        goto found_upper_layer;
    default:
        return LD_SCAN_ERR;
    }

found_upper_layer:
    if (frag_hdr_off) {
        if (VALIDATE_READ_DATA(skb, &frag_hdr, frag_hdr_off, sizeof(*frag_hdr))) {
            return LD_SCAN_ERR;
        }
        scanner_ctx->fragment_id = bpf_ntohl(frag_hdr->identification);

        u16 raw_off = bpf_ntohs(frag_hdr->frag_off);
        scanner_ctx->fragment_off = raw_off & IPV6_FRAG_OFFSET;

        bool mf = raw_off & IPV6_FRAG_MF;
        bool has_offset = scanner_ctx->fragment_off != 0;

        if (!has_offset && !mf) {
            scanner_ctx->fragment_type = FRAG_SINGLE;
        } else if (!has_offset && mf) {
            scanner_ctx->fragment_type = FRAG_FIRST;
        } else if (has_offset && mf) {
            scanner_ctx->fragment_type = FRAG_MIDDLE;
        } else {
            scanner_ctx->fragment_type = FRAG_LAST;
        }
    }

    scanner_ctx->l4_protocol = nexthdr;
    scanner_ctx->l4_offset = payload_relative_pos;

    return LD_SCAN_OK;
}

static __always_inline enum land_scan_result scan_ipv6_full(struct __sk_buff *skb, u32 l3_offset,
                                                            struct scan_ipv6_idx *idx) {
    struct ip_scanner_ctx ctx = {0};
    ctx.l4_offset = l3_offset;

    enum land_scan_result ret = scan_ipv6(skb, &ctx);
    if (ret) return ret;

    idx->fragment_off = ctx.fragment_off;
    idx->fragment_id = ctx.fragment_id;
    idx->fragment_type = ctx.fragment_type;
    idx->l4_protocol = ctx.l4_protocol;
    idx->l4_offset = ctx.l4_offset;
    idx->pkt_type = PKT_CONNLESS_V2;

    idx->icmp_error_l3_offset = 0;
    idx->icmp_error_inner_l4_offset = 0;
    idx->icmp_error_l4_protocol = 0;

    if (idx->fragment_type >= FRAG_MIDDLE) {
        idx->l4_offset = 0;
        return LD_SCAN_OK;
    }

    if (idx->l4_protocol == NEXTHDR_TCP) {
        struct tcphdr *tcph;
        if (VALIDATE_READ_DATA(skb, &tcph, idx->l4_offset, sizeof(*tcph))) return LD_SCAN_ERR;

        bool syn = tcph->syn;
        bool ack = tcph->ack;
        bool rst = tcph->rst;
        bool fin = tcph->fin;

        if (syn && !ack)
            idx->pkt_type = PKT_TCP_SYN_V2;
        else if (rst)
            idx->pkt_type = PKT_TCP_RST_V2;
        else if (fin)
            idx->pkt_type = PKT_TCP_FIN_V2;
        else if (ack)
            idx->pkt_type = PKT_TCP_ACK_V2;
        else
            idx->pkt_type = PKT_TCP_DATA_V2;

    } else if (idx->l4_protocol == NEXTHDR_UDP) {
        idx->pkt_type = PKT_CONNLESS_V2;

    } else if (idx->l4_protocol == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmp6h;
        if (VALIDATE_READ_DATA(skb, &icmp6h, idx->l4_offset, sizeof(struct icmp6hdr))) {
            return LD_SCAN_ERR;
        }

        switch (icmp6_msg_type(icmp6h)) {
        case ICMP_ERROR_MSG: {
            idx->icmp_error_l3_offset = idx->l4_offset + ICMP6_HDR_LEN;
            barrier_var(idx->icmp_error_l3_offset);

            struct ip_scanner_ctx inner_ctx = {0};
            inner_ctx.l4_offset = idx->icmp_error_l3_offset;
            if (scan_ipv6(skb, &inner_ctx)) return LD_SCAN_ERR;

            if (inner_ctx.fragment_type >= FRAG_MIDDLE) return LD_SCAN_ERR;

            idx->icmp_error_inner_l4_offset = inner_ctx.l4_offset;
            idx->icmp_error_l4_protocol = inner_ctx.l4_protocol;

            union u_ld_ip *temp_addr;
            union u_ld_ip dst_ip_val, icmp_src_ip_val;

            if (VALIDATE_READ_DATA(skb, &temp_addr, l3_offset + offsetof(struct ipv6hdr, daddr),
                                   sizeof(union u_ld_ip))) {
                return LD_SCAN_ERR;
            }
            COPY_ADDR_FROM(dst_ip_val.all, temp_addr->all);
            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr),
                                   sizeof(union u_ld_ip))) {
                return LD_SCAN_ERR;
            }
            COPY_ADDR_FROM(icmp_src_ip_val.all, temp_addr->all);

            if (!ld_ip_addr_equal(&dst_ip_val, &icmp_src_ip_val)) return LD_SCAN_ERR;
            break;
        }
        case ICMP_QUERY_MSG:
            idx->pkt_type = PKT_CONNLESS_V2;
            break;
        case ICMP_ACT_UNSPEC:
            return LD_SCAN_UNSPEC;
        default:
            return LD_SCAN_ERR;
        }
    }

    return LD_SCAN_OK;
}

static __always_inline enum land_scan_result
scan_ipv6_into_idx(struct __sk_buff *skb, u32 l3_offset, struct scan_ipv6_idx *idx) {
    struct ip_scanner_ctx ctx = {.l4_offset = l3_offset};
    if (scan_ipv6(skb, &ctx)) return LD_SCAN_ERR;

    idx->fragment_off = ctx.fragment_off;
    idx->fragment_id = ctx.fragment_id;
    idx->fragment_type = ctx.fragment_type;
    idx->l4_protocol = ctx.l4_protocol;
    idx->l4_offset = ctx.l4_offset;
    idx->pkt_type = PKT_CONNLESS_V2;

    idx->icmp_error_l3_offset = 0;
    idx->icmp_error_inner_l4_offset = 0;
    idx->icmp_error_l4_protocol = 0;

    if (idx->fragment_type >= FRAG_MIDDLE) idx->l4_offset = 0;

    return LD_SCAN_OK;
}

static __always_inline bool scan_ipv6_upgrade_icmp(struct __sk_buff *skb, u32 l3_offset,
                                                   struct scan_ipv6_idx *idx,
                                                   struct in6_addr *saddr) {
    struct icmp6hdr *icmp6h;
    if (VALIDATE_READ_DATA(skb, &icmp6h, idx->l4_offset, sizeof(struct icmp6hdr))) return false;

    if (icmp6_msg_type(icmp6h) != ICMP_ERROR_MSG) return false;

    idx->icmp_error_l3_offset = idx->l4_offset + ICMP6_HDR_LEN;
    barrier_var(idx->icmp_error_l3_offset);

    struct ip_scanner_ctx inner_ctx = {.l4_offset = idx->icmp_error_l3_offset};
    if (scan_ipv6(skb, &inner_ctx) || inner_ctx.fragment_type >= FRAG_MIDDLE) return false;

    idx->icmp_error_inner_l4_offset = inner_ctx.l4_offset;
    idx->icmp_error_l4_protocol = inner_ctx.l4_protocol;

    union u_ld_ip *temp_addr;
    union u_ld_ip dst_ip_val, icmp_src_ip_val;
    if (VALIDATE_READ_DATA(skb, &temp_addr, l3_offset + offsetof(struct ipv6hdr, daddr),
                           sizeof(union u_ld_ip)))
        return false;
    COPY_ADDR_FROM(dst_ip_val.all, temp_addr->all);
    if (VALIDATE_READ_DATA(skb, &temp_addr,
                           idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr),
                           sizeof(union u_ld_ip)))
        return false;
    COPY_ADDR_FROM(icmp_src_ip_val.all, temp_addr->all);

    if (!ld_ip_addr_equal(&dst_ip_val, &icmp_src_ip_val)) return false;

    struct ipv6hdr *inner_ip6h;
    if (VALIDATE_READ_DATA(skb, &inner_ip6h, idx->icmp_error_l3_offset, sizeof(*inner_ip6h)))
        return false;
    *saddr = inner_ip6h->daddr;
    return true;
}

#endif /* __LD_SKB_SCANNER6_H__ */
