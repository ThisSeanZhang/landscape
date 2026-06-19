#ifndef __LD_XDP_SCANNER6_H__
#define __LD_XDP_SCANNER6_H__

#include "scan_types.h"
#include "xdp_common.h"

static __always_inline enum xdp_scan_status xdp_scan_ipv6(struct xdp_md *ctx, u16 l3_offset,
                                                          struct scan_ipv6_idx *idx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ipv6hdr *ip6h = data + l3_offset;
    if (xdp_no_room(ip6h + 1, data_end)) return XDP_SCAN_ERR;

    if (ip6h->version != 6) return XDP_SCAN_ERR;

    u32 payload_pos = l3_offset + sizeof(*ip6h);
    u8 nexthdr = ip6h->nexthdr;
    u32 frag_hdr_off = 0;

#pragma unroll
    for (int i = 0; i < LD_MAX_IPV6_EXT_NUM; i++) {
        switch (nexthdr) {
        case NEXTHDR_AUTH:
            return XDP_SCAN_UNSPEC;
        case NEXTHDR_FRAGMENT: {
            struct frag_hdr *fh = data + payload_pos;
            if (xdp_no_room(fh + 1, data_end)) return XDP_SCAN_ERR;
            frag_hdr_off = payload_pos;
            nexthdr = fh->nexthdr;
            payload_pos += sizeof(*fh);
            break;
        }
        case NEXTHDR_HOP:
        case NEXTHDR_ROUTING:
        case NEXTHDR_DEST: {
            struct ipv6_opt_hdr *oh = data + payload_pos;
            if (xdp_no_room(oh + 1, data_end)) return XDP_SCAN_ERR;
            payload_pos += (oh->hdrlen + 1) * 8;
            nexthdr = oh->nexthdr;
            break;
        }
        default:
            goto found;
        }
    }

    switch (nexthdr) {
    case NEXTHDR_TCP:
    case NEXTHDR_UDP:
    case NEXTHDR_ICMP:
        goto found;
    default:
        return XDP_SCAN_ERR;
    }

found:
    if (frag_hdr_off) {
        struct frag_hdr *fh = data + frag_hdr_off;
        if (xdp_no_room(fh + 1, data_end)) return XDP_SCAN_ERR;

        idx->fragment_id = bpf_ntohl(fh->identification);

        u16 raw_off = bpf_ntohs(fh->frag_off);
        idx->fragment_off = raw_off & IPV6_FRAG_OFFSET;

        bool mf = raw_off & IPV6_FRAG_MF;
        bool has_offset = idx->fragment_off != 0;

        if (!has_offset && !mf) {
            idx->fragment_type = FRAG_SINGLE;
        } else if (!has_offset && mf) {
            idx->fragment_type = FRAG_FIRST;
        } else if (has_offset && mf) {
            idx->fragment_type = FRAG_MIDDLE;
        } else {
            idx->fragment_type = FRAG_LAST;
        }
    } else {
        idx->fragment_type = FRAG_SINGLE;
        idx->fragment_id = 0;
        idx->fragment_off = 0;
    }

    idx->l4_protocol = nexthdr;
    idx->l4_offset = (u16)payload_pos;

    return XDP_SCAN_OK;
}

static int ipv6_icmp_msg_type(struct icmp6hdr *icmp6h) {
    switch (icmp6h->icmp6_type) {
    case ICMPV6_DEST_UNREACH:
    case ICMPV6_PKT_TOOBIG:
    case ICMPV6_TIME_EXCEED:
    case ICMPV6_PARAMPROB:
        return ICMP_ERROR_MSG;
    case ICMPV6_ECHO_REQUEST:
    case ICMPV6_ECHO_REPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline enum xdp_scan_status xdp_scan_ipv6_full(struct xdp_md *ctx, u16 l3_offset,
                                                               struct scan_ipv6_idx *idx) {
    enum xdp_scan_status ret = xdp_scan_ipv6(ctx, l3_offset, idx);
    if (ret) return ret;

    idx->icmp_error_l3_offset = 0;
    idx->icmp_error_inner_l4_offset = 0;
    idx->icmp_error_l4_protocol = 0;

    if (idx->fragment_type >= FRAG_MIDDLE) return XDP_SCAN_OK;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (idx->l4_protocol == NEXTHDR_TCP) {
        struct tcphdr *tcph = data + idx->l4_offset;
        if (xdp_no_room(tcph + 1, data_end)) return XDP_SCAN_ERR;

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

    } else if (idx->l4_protocol == NEXTHDR_ICMP) {
        struct icmp6hdr *icmp6h = data + idx->l4_offset;
        if (xdp_no_room(icmp6h + 1, data_end)) return XDP_SCAN_ERR;

        switch (ipv6_icmp_msg_type(icmp6h)) {
        case ICMP_ERROR_MSG: {
            idx->icmp_error_l3_offset = idx->l4_offset + ICMP6_HDR_LEN;
            barrier_var(idx->icmp_error_l3_offset);

            struct scan_ipv6_idx inner = {};
            if (xdp_scan_ipv6(ctx, idx->icmp_error_l3_offset, &inner)) return XDP_SCAN_ERR;

            if (inner.fragment_off != 0) return XDP_SCAN_ERR;

            idx->icmp_error_inner_l4_offset = inner.l4_offset;
            idx->icmp_error_l4_protocol = inner.l4_protocol;

            struct ipv6hdr *outer = data + l3_offset;
            struct ipv6hdr *inner_ip6 = data + idx->icmp_error_l3_offset;

            if (xdp_no_room(outer + 1, data_end)) return XDP_SCAN_ERR;
            if (xdp_no_room(inner_ip6 + 1, data_end)) return XDP_SCAN_ERR;

            inet6_addr outer_daddr, inner_saddr;
            COPY_ADDR_FROM(outer_daddr.all, outer->daddr.in6_u.u6_addr32);
            COPY_ADDR_FROM(inner_saddr.all, inner_ip6->saddr.in6_u.u6_addr32);

            if (!inet6_addr_equal(&outer_daddr, &inner_saddr)) return XDP_SCAN_ERR;
            break;
        }
        case ICMP_QUERY_MSG:
            idx->pkt_type = PKT_CONNLESS_V2;
            break;
        default:
            return XDP_SCAN_UNSPEC;
        }
    }

    return XDP_SCAN_OK;
}

#endif /* __LD_XDP_SCANNER6_H__ */
