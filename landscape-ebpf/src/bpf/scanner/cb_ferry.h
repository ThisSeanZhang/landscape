#ifndef __LD_CB_FERRY_H__
#define __LD_CB_FERRY_H__

#include "base/proto_def.h"
#include "chain/tc_cb.h"
#include "scanner/skb_scanner4.h"
#include "scanner/skb_scanner6.h"
#include "scanner/skb_read.h"
#include "fragment/frag_common.h"

/*
 * cb ferry: the chain roots scan the packet once and pack the layout /
 * ports / fragment results into skb->cb; stages unpack instead of
 * rescanning.  A root whose scan fails (or a cb the stage does not
 * recognise) makes the stage fall back to its own scan, so behaviour is
 * unchanged whenever the ferry is absent.
 *
 * The root reuses scan_*_full + skb_read_*_info verbatim for extraction,
 * and keeps its own private frag_cache instance (FIRST write / MIDDLE-LAST
 * lookup), so per-object map separation is preserved.
 */

// ── root side ──

static __always_inline void ferry_store(struct __sk_buff *skb, u32 fwd, u16 l4_offset,
                                        u8 l4_protocol, u8 pkt_type, u16 icmp_inner_l4,
                                        u8 icmp_l4_protocol, __be16 sport, __be16 dport,
                                        bool ports_valid, u8 frag_code) {
    skb->cb[2] = (u32)l4_offset | ((u32)l4_protocol << 16) | ((u32)pkt_type << 24);
    skb->cb[3] = (u32)sport | ((u32)dport << 16);
    skb->cb[4] = (u32)icmp_inner_l4 | ((u32)icmp_l4_protocol << 16);
    u32 bitmap = 1 | ((u32)ports_valid << 1) | ((u32)frag_code << 2);
    skb->cb[0] = fwd | (TC_CB_FERRY_MAGIC << 1) | (bitmap << 16);
}

static __always_inline int ferry_frag4_cache(struct __sk_buff *skb, u32 l3_offset,
                                             const struct scan_ipv4_idx *idx, __be16 *sport,
                                             __be16 *dport) {
    struct iphdr *iph;
    if (VALIDATE_READ_DATA(skb, &iph, l3_offset, sizeof(*iph))) return TC_ACT_SHOT;

    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV4_TYPE;
    key.l4proto = idx->l4_protocol;
    key.id = idx->fragment_id;
    key.saddr.in6_u.u6_addr32[0] = iph->saddr;
    key.daddr.in6_u.u6_addr32[0] = iph->daddr;

    if (idx->fragment_type == FRAG_FIRST) {
        struct frag_cache_value value = {
            .sport = *sport,
            .dport = *dport,
        };
        if (bpf_map_update_elem(&frag_cache, &key, &value, BPF_ANY)) return TC_ACT_SHOT;
        return TC_ACT_OK;
    }

    struct frag_cache_value *value = bpf_map_lookup_elem(&frag_cache, &key);
    if (!value) return TC_ACT_SHOT;
    *sport = value->sport;
    *dport = value->dport;
    return TC_ACT_OK;
}

static __always_inline int ferry_frag6_cache(struct __sk_buff *skb, u32 l3_offset,
                                             const struct scan_ipv6_idx *idx, __be16 *sport,
                                             __be16 *dport) {
    struct ipv6hdr *ip6h;
    if (VALIDATE_READ_DATA(skb, &ip6h, l3_offset, sizeof(*ip6h))) return TC_ACT_SHOT;

    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV6_TYPE;
    key.l4proto = idx->l4_protocol;
    key.id = idx->fragment_id;
    COPY_ADDR_FROM(key.saddr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(key.daddr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);

    if (idx->fragment_type == FRAG_FIRST) {
        struct frag_cache_value value = {
            .sport = *sport,
            .dport = *dport,
        };
        if (bpf_map_update_elem(&frag_cache, &key, &value, BPF_ANY)) return TC_ACT_SHOT;
        return TC_ACT_OK;
    }

    struct frag_cache_value *value = bpf_map_lookup_elem(&frag_cache, &key);
    if (!value) return TC_ACT_SHOT;
    *sport = value->sport;
    *dport = value->dport;
    return TC_ACT_OK;
}

static __always_inline void ferry_root_pack_v4(struct __sk_buff *skb, u32 l3_offset) {
    u32 fwd = skb->cb[0] & 1;

    struct scan_ipv4_idx idx = {};
    if (scan_ipv4_full(skb, l3_offset, &idx) != LD_SCAN_OK) {
        skb->cb[0] = fwd | (TC_CB_FERRY_MAGIC << 1);
        return;
    }

    __be16 sport = 0, dport = 0;
    bool ports_valid = true;

    if (idx.icmp_error_l3_offset > 0 && idx.fragment_type != FRAG_SINGLE) {
        // fragmented icmp error: today's frag_track SHOTs it (nat) while
        // fw passes; PORTS_INVALID reproduces both verdicts.
        ports_valid = false;
    } else if (idx.fragment_type >= FRAG_MIDDLE) {
        if (ferry_frag4_cache(skb, l3_offset, &idx, &sport, &dport) != TC_ACT_OK) {
            ports_valid = false;
        }
    } else {
        struct inet4_pair pair = {0};
        if (skb_read_ipv4_info(skb, l3_offset, &idx, &pair) != TC_ACT_OK) {
            ports_valid = false;
        } else if (idx.fragment_type == FRAG_FIRST &&
                   ferry_frag4_cache(skb, l3_offset, &idx, &pair.src_port, &pair.dst_port) !=
                       TC_ACT_OK) {
            ports_valid = false;
        }
        sport = pair.src_port;
        dport = pair.dst_port;
    }

    ferry_store(skb, fwd, idx.l4_offset, idx.l4_protocol, idx.pkt_type,
                idx.icmp_error_inner_l4_offset, idx.icmp_error_l4_protocol, sport, dport,
                ports_valid, idx.fragment_type);
}

static __always_inline void ferry_root_pack_v6(struct __sk_buff *skb, u32 l3_offset) {
    u32 fwd = skb->cb[0] & 1;

    struct scan_ipv6_idx idx = {};
    if (scan_ipv6_full(skb, l3_offset, &idx) != LD_SCAN_OK) {
        skb->cb[0] = fwd | (TC_CB_FERRY_MAGIC << 1);
        return;
    }

    __be16 sport = 0, dport = 0;
    bool ports_valid = true;
    u8 frag_code = idx.frag_hdr_present && idx.fragment_type == FRAG_SINGLE ? TC_CB_FRAG_SINGLE_V6H
                                                                            : idx.fragment_type;

    if (idx.icmp_error_l3_offset > 0 && idx.fragment_type != FRAG_SINGLE) {
        ports_valid = false;
    } else if (idx.fragment_type >= FRAG_MIDDLE) {
        if (ferry_frag6_cache(skb, l3_offset, &idx, &sport, &dport) != TC_ACT_OK) {
            ports_valid = false;
        }
    } else {
        struct inet_pair pair = {0};
        if (skb_read_ipv6_info(skb, l3_offset, &idx, &pair) != TC_ACT_OK) {
            ports_valid = false;
        } else if (idx.fragment_type == FRAG_FIRST &&
                   ferry_frag6_cache(skb, l3_offset, &idx, &pair.src_port, &pair.dst_port) !=
                       TC_ACT_OK) {
            ports_valid = false;
        }
        sport = pair.src_port;
        dport = pair.dst_port;
    }

    ferry_store(skb, fwd, idx.l4_offset, idx.l4_protocol, idx.pkt_type,
                idx.icmp_error_inner_l4_offset, idx.icmp_error_l4_protocol, sport, dport,
                ports_valid, frag_code);
}

// ── stage side ──

static __always_inline bool cb_ferry_load_v4(struct __sk_buff *skb, u32 l3_offset,
                                             struct scan_ipv4_idx *idx, struct inet4_pair *pair) {
    if (!tc_cb_ferry_valid(skb)) return false;

    idx->l4_offset = tc_cb_l4_offset(skb);
    idx->l4_protocol = tc_cb_l4_protocol(skb);
    idx->pkt_type = tc_cb_pkt_type(skb);
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
    idx->pkt_type = tc_cb_pkt_type(skb);
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
