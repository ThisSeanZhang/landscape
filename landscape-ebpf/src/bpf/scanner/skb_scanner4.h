#ifndef __LD_SKB_SCANNER4_H__
#define __LD_SKB_SCANNER4_H__

#include "skb_common.h"

static __always_inline enum land_scan_result scan_ipv4(struct __sk_buff *skb,
                                                       struct ip_scanner_ctx *scanner_ctx) {
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, scanner_ctx->l4_offset, sizeof(struct iphdr))) {
        return LD_SCAN_ERR;
    }

    if (iph->version != 4) {
        return LD_SCAN_ERR;
    }

    u16 frag_off_host = bpf_ntohs(iph->frag_off);
    scanner_ctx->fragment_off = (frag_off_host & LD_IP_OFFSET) << 3;

    bool mf = frag_off_host & LD_IP_MF;
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

    scanner_ctx->fragment_id = bpf_ntohs(iph->id);
    scanner_ctx->l4_protocol = iph->protocol;
    scanner_ctx->l4_offset += (iph->ihl * 4);

    return LD_SCAN_OK;
}

static __always_inline enum land_scan_result scan_ipv4_full(struct __sk_buff *skb, u32 l3_offset,
                                                            struct scan_ipv4_idx *idx) {
    struct ip_scanner_ctx ctx = {0};
    ctx.l4_offset = l3_offset;

    enum land_scan_result ret = scan_ipv4(skb, &ctx);
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

    if (idx->l4_protocol == IPPROTO_TCP) {
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

    } else if (idx->l4_protocol == IPPROTO_UDP) {
        idx->pkt_type = PKT_CONNLESS_V2;

    } else if (idx->l4_protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph;
        if (VALIDATE_READ_DATA(skb, &icmph, idx->l4_offset, sizeof(struct icmphdr))) {
            return LD_SCAN_ERR;
        }

        switch (icmp_msg_type(icmph)) {
        case ICMP_ERROR_MSG: {
            idx->icmp_error_l3_offset = idx->l4_offset + ICMP_HDR_LEN;
            barrier_var(idx->icmp_error_l3_offset);

            struct ip_scanner_ctx inner_ctx = {0};
            inner_ctx.l4_offset = idx->icmp_error_l3_offset;
            if (scan_ipv4(skb, &inner_ctx)) return LD_SCAN_ERR;

            if (inner_ctx.fragment_off) return LD_SCAN_ERR;

            idx->icmp_error_inner_l4_offset = inner_ctx.l4_offset;
            idx->icmp_error_l4_protocol = inner_ctx.l4_protocol;

            u32 *temp_addr;
            u32 dst_ip_val, icmp_src_ip_val;
            if (VALIDATE_READ_DATA(skb, &temp_addr, l3_offset + offsetof(struct iphdr, daddr),
                                   sizeof(u32))) {
                return LD_SCAN_ERR;
            }
            dst_ip_val = *temp_addr;
            if (VALIDATE_READ_DATA(skb, &temp_addr,
                                   idx->icmp_error_l3_offset + offsetof(struct iphdr, saddr),
                                   sizeof(u32))) {
                return LD_SCAN_ERR;
            }
            icmp_src_ip_val = *temp_addr;

            if (dst_ip_val != icmp_src_ip_val) return LD_SCAN_ERR;
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

#endif /* __LD_SKB_SCANNER4_H__ */
