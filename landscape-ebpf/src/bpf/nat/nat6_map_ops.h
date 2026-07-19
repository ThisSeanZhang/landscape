#ifndef __LD_NAT6_MAP_OPS_H__
#define __LD_NAT6_MAP_OPS_H__

#include "nat_common.h"
#include "nat6_static.h"

static __always_inline int nat6_l4_checksum(u32 l4_offset, u8 l4_protocol,
                                            u32 *l4_checksum_offset) {
    if (l4_protocol == IPPROTO_TCP) {
        *l4_checksum_offset = l4_offset + offsetof(struct tcphdr, check);
    } else if (l4_protocol == IPPROTO_UDP) {
        *l4_checksum_offset = l4_offset + offsetof(struct udphdr, check);
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        *l4_checksum_offset = l4_offset + offsetof(struct icmp6hdr, icmp6_cksum);
    } else {
        return NAT_OP_ERR;
    }
    return NAT_OP_OK;
}

static __always_inline bool nat6_is_same_prefix(const u8 prefix[8], const union u_inet_addr *a,
                                                u8 npt_id_mask) {
    const u8 *b = a->bits;
    u8 prefix_mask = (u8)~npt_id_mask;
    return prefix[0] == b[0] && prefix[1] == b[1] && prefix[2] == b[2] && prefix[3] == b[3] &&
           prefix[4] == b[4] && prefix[5] == b[5] && prefix[6] == b[6] &&
           ((prefix[7] & prefix_mask) == (b[7] & prefix_mask));
}

static __always_inline bool
nat6_static_needs_prefix_replace(const struct static_nat6_mapping_value *value) {
    return value->lan_prefix[0] != 0 || value->lan_prefix[1] != 0 || value->lan_prefix[2] != 0 ||
           value->lan_prefix[3] != 0 || value->lan_prefix[4] != 0 || value->lan_prefix[5] != 0 ||
           value->lan_prefix[6] != 0 || value->lan_prefix[7] != 0;
}

static __always_inline struct static_nat6_mapping_value *
nat6_check_egress_static(u8 ip_protocol, const struct inet_pair *pkt_ip_pair) {
    struct static_nat6_mapping_key egress_key = {0};
    struct static_nat6_mapping_value *value;

    egress_key.l4_protocol = ip_protocol;

    egress_key.port = pkt_ip_pair->src_port;
    __builtin_memcpy(egress_key.ip_suffix, pkt_ip_pair->src_addr.bits + 8, 8);
    value = bpf_map_lookup_elem(&nat6_static_map, &egress_key);
    if (value) {
        return value;
    }

    egress_key.port = 0;
    return bpf_map_lookup_elem(&nat6_static_map, &egress_key);
}

static __always_inline int nat6_check_ingress_static(u8 ip_protocol,
                                                     const struct inet_pair *pkt_ip_pair,
                                                     __be64 *local_client_prefix) {
    struct static_nat6_mapping_key ingress_key = {0};
    struct static_nat6_mapping_value *value = NULL;

    ingress_key.l4_protocol = ip_protocol;
    ingress_key.port = pkt_ip_pair->dst_port;
    __builtin_memcpy(ingress_key.ip_suffix, pkt_ip_pair->dst_addr.bits + 8, 8);

    value = bpf_map_lookup_elem(&nat6_static_map, &ingress_key);
    if (value) {
        goto process_mapping_value;
    }

    ingress_key.port = 0;
    value = bpf_map_lookup_elem(&nat6_static_map, &ingress_key);
    if (!value) {
        return NAT6_STATIC_MISS;
    }

process_mapping_value:
    if (!nat6_static_needs_prefix_replace(value)) {
        return NAT6_STATIC_PASS;
    }

    COPY_ADDR_FROM(local_client_prefix, value->lan_prefix);
    return NAT6_STATIC_REPLACE;
}

#endif /* __LD_NAT6_MAP_OPS_H__ */
