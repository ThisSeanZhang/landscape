#ifndef __LD_CB_FERRY_H__
#define __LD_CB_FERRY_H__

#include "base/landscape.h"
#include "base/proto_def.h"
#include "base/tcp_phase.h"
#include "chain/tc_cb.h"
#include "scanner/scan_types.h"

/*
 * Legacy stage-side cb unpacking. New chain roots publish the cb through
 * reader/tc_ferry_root.h; this helper only translates the canonical layout
 * back into the old scanner index for stages that have not migrated yet.
 */

// ── stage side ──

/* The canonical cb field is tcp_phase; legacy scanners/stages still key off
 * einat's PKT_* enum. Keep the translation here until the old tc_nat4 path
 * is removed. */
static __always_inline u8 cb_pkt_type_from_tcp_phase(const struct __sk_buff *skb) {
    if (tc_cb_icmp_inner_l4(skb)) return PKT_CONNLESS_V2;
    if (!tc_cb_frag_single(skb) && tc_cb_frag(skb) >= FRAG_MIDDLE) return PKT_CONNLESS_V2;
    if (tc_cb_l4_protocol(skb) != IPPROTO_TCP) return PKT_CONNLESS_V2;

    switch (tc_cb_tcp_phase(skb)) {
    case NAPT_TCP_PHASE_SYN:
        return PKT_TCP_SYN_V2;
    case NAPT_TCP_PHASE_RST:
        return PKT_TCP_RST_V2;
    case NAPT_TCP_PHASE_FIN:
        return PKT_TCP_FIN_V2;
    case NAPT_TCP_PHASE_ESTABLISHED:
        return PKT_TCP_ACK_V2;
    default:
        return PKT_TCP_DATA_V2;
    }
}

static __always_inline bool cb_ferry_load_v4(struct __sk_buff *skb, u32 l3_offset,
                                             struct scan_ipv4_idx *idx, struct inet4_pair *pair) {
    if (!tc_cb_ferry_valid(skb)) return false;

    idx->l4_offset = tc_cb_l4_offset(skb);
    idx->l4_protocol = tc_cb_l4_protocol(skb);
    idx->pkt_type = cb_pkt_type_from_tcp_phase(skb);
    idx->fragment_type = tc_cb_frag(skb);
    idx->fragment_off = 0;
    idx->fragment_id = 0;
    idx->icmp_error_inner_l4_offset = tc_cb_icmp_inner_l4(skb);
    idx->icmp_error_l4_protocol = tc_cb_icmp_l4_protocol(skb);
    idx->icmp_error_l3_offset = idx->icmp_error_inner_l4_offset ? idx->l4_offset + ICMP_HDR_LEN : 0;

    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, l3_offset, sizeof(*iph))) return false;
    pair->src_addr.addr = iph->saddr;
    pair->dst_addr.addr = iph->daddr;

    if (idx->icmp_error_l3_offset) {
        struct iphdr *inner_ip;
        if (VALIDATE_READ_DATA(skb, &inner_ip, idx->icmp_error_l3_offset, sizeof(*inner_ip)))
            return false;
        pair->src_addr.addr = inner_ip->daddr;
    }

    pair->src_port = tc_cb_sport(skb);
    pair->dst_port = tc_cb_dport(skb);
    return true;
}

static __always_inline bool cb_ferry_load_v6(struct __sk_buff *skb, u32 l3_offset,
                                             struct scan_ipv6_idx *idx, struct inet_pair *pair) {
    if (!tc_cb_ferry_valid(skb)) return false;

    idx->l4_offset = tc_cb_l4_offset(skb);
    idx->l4_protocol = tc_cb_l4_protocol(skb);
    idx->pkt_type = cb_pkt_type_from_tcp_phase(skb);
    idx->fragment_type = tc_cb_frag(skb) == TC_CB_FRAG_SINGLE_V6H ? FRAG_SINGLE : tc_cb_frag(skb);
    idx->frag_hdr_present = tc_cb_frag(skb) == TC_CB_FRAG_SINGLE_V6H;
    idx->fragment_off = 0;
    idx->fragment_id = 0;
    idx->icmp_error_inner_l4_offset = tc_cb_icmp_inner_l4(skb);
    idx->icmp_error_l4_protocol = tc_cb_icmp_l4_protocol(skb);
    idx->icmp_error_l3_offset =
        idx->icmp_error_inner_l4_offset ? idx->l4_offset + ICMP6_HDR_LEN : 0;

    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) return false;
    COPY_ADDR_FROM(pair->src_addr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(pair->dst_addr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);

    if (idx->icmp_error_l3_offset) {
        struct ipv6hdr *inner_ip6;
        if (VALIDATE_READ_DATA(skb, &inner_ip6, idx->icmp_error_l3_offset, sizeof(*inner_ip6)))
            return false;
        COPY_ADDR_FROM(pair->src_addr.in6_u.u6_addr32, inner_ip6->daddr.in6_u.u6_addr32);
    }

    pair->src_port = tc_cb_sport(skb);
    pair->dst_port = tc_cb_dport(skb);
    return true;
}

#endif /* __LD_CB_FERRY_H__ */
