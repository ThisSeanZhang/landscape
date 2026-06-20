#ifndef __LD_XDP_SCANNER4_H__
#define __LD_XDP_SCANNER4_H__

#include "scan_types.h"
#include "xdp_common.h"

static __always_inline enum xdp_scan_status xdp_scan_ipv4(struct xdp_md *ctx, u16 l3_offset,
                                                          struct scan_ipv4_idx *idx) {
    void *data, *data_end;
    struct iphdr *iph;

    if (XDP_REVALIDATE(ctx, &data, &data_end, &iph, l3_offset, sizeof(*iph))) return XDP_SCAN_ERR;

    if (iph->version != 4) return XDP_SCAN_ERR;

    if (iph->ihl < 5) return XDP_SCAN_ERR;

    u16 frag_off_host = bpf_ntohs(iph->frag_off);
    idx->fragment_off = (frag_off_host & LD_IP_OFFSET);

    bool mf = frag_off_host & LD_IP_MF;
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

    idx->fragment_id = bpf_ntohs(iph->id);
    idx->l4_protocol = iph->protocol;

    u16 l4_off = l3_offset + (iph->ihl * 4);
    if (xdp_no_room(data + l4_off, data_end)) return XDP_SCAN_ERR;

    idx->l4_offset = l4_off;
    return XDP_SCAN_OK;
}

static __always_inline int ipv4_icmp_msg_type(struct icmphdr *icmph) {
    switch (icmph->type) {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
        return ICMP_ERROR_MSG;
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline enum xdp_scan_status xdp_scan_ipv4_full(struct xdp_md *ctx, u16 l3_offset,
                                                               struct scan_ipv4_idx *idx) {
    enum xdp_scan_status ret = xdp_scan_ipv4(ctx, l3_offset, idx);
    if (ret) return ret;

    idx->icmp_error_l3_offset = 0;
    idx->icmp_error_inner_l4_offset = 0;
    idx->icmp_error_l4_protocol = 0;

    if (idx->fragment_type >= FRAG_MIDDLE) return XDP_SCAN_OK;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (idx->l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + idx->l4_offset;
        if (xdp_no_room(tcph + 1, data_end)) return XDP_SCAN_ERR;

        bool syn = tcph->syn;
        bool ack = tcph->ack;
        bool rst = tcph->rst;
        bool fin = tcph->fin;

        if (syn)
            idx->pkt_type = PKT_TCP_SYN_V2;
        else if (rst)
            idx->pkt_type = PKT_TCP_RST_V2;
        else if (fin)
            idx->pkt_type = PKT_TCP_FIN_V2;
        else if (ack)
            idx->pkt_type = PKT_TCP_ACK_V2;
        else
            idx->pkt_type = PKT_TCP_DATA_V2;

    } else if (idx->l4_protocol == IPPROTO_UDP) {
        idx->pkt_type = PKT_CONNLESS_V2;

    } else if (idx->l4_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = data + idx->l4_offset;
        if (xdp_no_room(icmph + 1, data_end)) return XDP_SCAN_ERR;

        switch (ipv4_icmp_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            idx->icmp_error_l3_offset = idx->l4_offset + ICMP_HDR_LEN;
            barrier_var(idx->icmp_error_l3_offset);

            struct scan_ipv4_idx inner = {};
            if (xdp_scan_ipv4(ctx, idx->icmp_error_l3_offset, &inner)) return XDP_SCAN_ERR;

            if (inner.fragment_type >= FRAG_MIDDLE) return XDP_SCAN_ERR;

            idx->icmp_error_inner_l4_offset = inner.l4_offset;
            idx->icmp_error_l4_protocol = inner.l4_protocol;

            struct iphdr *outer = data + l3_offset;
            struct iphdr *inner_ip = data + idx->icmp_error_l3_offset;

            if (xdp_no_room(outer + 1, data_end)) return XDP_SCAN_ERR;
            if (xdp_no_room(inner_ip + 1, data_end)) return XDP_SCAN_ERR;

            if (outer->daddr != inner_ip->saddr) return XDP_SCAN_ERR;
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

#endif /* __LD_XDP_SCANNER4_H__ */
