#ifndef __LD_TPROXY_PACKET_H__
#define __LD_TPROXY_PACKET_H__

#include "base/ipv4.h"
#include "base/ipv6.h"
#include "base/landscape.h"
#include "base/proto_def.h"

struct tproxy_view {
    u8 l3_protocol;
    u8 l4_protocol;
    u16 l4_offset;
};

#define TPROXY_MAX_PULL 160U

static __always_inline int tproxy_read_data(struct __sk_buff *skb, u32 offset, u32 len,
                                            void **ptr) {
    if ((u64)offset + len > MAX_OFFSET) return -1;

    char *data = (char *)(long)skb->data;
    char *data_end = (char *)(long)skb->data_end;
    char *p = data + offset;
    if (p + len > data_end) return -1;

    *ptr = p;
    return 0;
}

static __always_inline int tproxy_pull_headers(struct __sk_buff *skb) {
    u32 need = skb->len;
    if (need > TPROXY_MAX_PULL) need = TPROXY_MAX_PULL;
    return bpf_skb_pull_data(skb, need);
}

static __always_inline int scan_tproxy_ipv4(struct __sk_buff *skb, u32 l3_offset,
                                            struct tproxy_view *view, struct inet_pair *pair) {
    struct iphdr *iph;
    if (tproxy_read_data(skb, l3_offset, sizeof(*iph), (void **)&iph)) return TC_ACT_SHOT;
    if (iph->version != IPV4_VERSION) return TC_ACT_SHOT;

    __u32 ihl = (__u32)iph->ihl;
    if (ihl < IPV4_IHL_MIN || ihl > IPV4_IHL_MAX) return TC_ACT_SHOT;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (frag_off & IPV4_FRAG_OFFSET_MASK) return TC_ACT_SHOT;

    pair->src_addr.in6_u.u6_addr32[0] = iph->saddr;
    pair->dst_addr.in6_u.u6_addr32[0] = iph->daddr;

    view->l3_protocol = LANDSCAPE_IPV4_TYPE;
    view->l4_protocol = iph->protocol;
    view->l4_offset = l3_offset + ihl * 4U;
    return TC_ACT_OK;
}

static __always_inline int scan_tproxy_ipv6(struct __sk_buff *skb, u32 l3_offset,
                                            struct tproxy_view *view, struct inet_pair *pair) {
    struct ipv6hdr *ip6h;
    if (tproxy_read_data(skb, l3_offset, sizeof(*ip6h), (void **)&ip6h)) return TC_ACT_SHOT;
    if (ip6h->version != IPV6_VERSION) return TC_ACT_SHOT;

    COPY_ADDR_FROM(pair->src_addr.in6_u.u6_addr32, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(pair->dst_addr.in6_u.u6_addr32, ip6h->daddr.in6_u.u6_addr32);

    __u8 next = ip6h->nexthdr;
    __u32 offset = l3_offset + IPV6_HDR_LEN;

    for (__u32 i = 0; i < 8U; i++) {
        if (next == IPV6_NH_FRAGMENT) {
            struct frag_hdr *frag;
            if (tproxy_read_data(skb, offset, sizeof(*frag), (void **)&frag)) return TC_ACT_SHOT;
            if (ipv6_frag_offset(frag->frag_off) != 0) return TC_ACT_SHOT;

            next = frag->nexthdr;
            offset += sizeof(*frag);
            continue;
        }

        if (next == IPV6_NH_HOPOPTS || next == IPV6_NH_ROUTING || next == IPV6_NH_DSTOPTS) {
            struct ipv6_opt_hdr *ext;
            if (tproxy_read_data(skb, offset, sizeof(*ext), (void **)&ext)) return TC_ACT_SHOT;

            __u32 ext_len = ipv6_opt_len(ext);
            if (ext_len < sizeof(*ext)) return TC_ACT_SHOT;

            next = ext->nexthdr;
            offset += ext_len;
            continue;
        }

        break;
    }

    view->l3_protocol = LANDSCAPE_IPV6_TYPE;
    view->l4_protocol = next;
    view->l4_offset = offset;
    return TC_ACT_OK;
}

static __always_inline int scan_tproxy_packet(struct __sk_buff *skb, u32 l3_offset,
                                              struct tproxy_view *view, struct inet_pair *pair) {
    if (tproxy_pull_headers(skb) != 0) return TC_ACT_SHOT;

    struct ethhdr *eth;
    if (tproxy_read_data(skb, 0, sizeof(*eth), (void **)&eth)) return TC_ACT_SHOT;

    if (eth->h_proto == ETH_IPV4) return scan_tproxy_ipv4(skb, l3_offset, view, pair);
    if (eth->h_proto == ETH_IPV6) return scan_tproxy_ipv6(skb, l3_offset, view, pair);
    return TC_ACT_UNSPEC;
}

static __always_inline int read_tproxy_packet_info(struct __sk_buff *skb,
                                                   const struct tproxy_view *view,
                                                   struct inet_pair *pair) {
    if (view->l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph;
        if (tproxy_read_data(skb, view->l4_offset, sizeof(*tcph), (void **)&tcph))
            return TC_ACT_SHOT;
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (view->l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph;
        if (tproxy_read_data(skb, view->l4_offset, sizeof(*udph), (void **)&udph))
            return TC_ACT_SHOT;
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
}

#endif /* __LD_TPROXY_PACKET_H__ */
