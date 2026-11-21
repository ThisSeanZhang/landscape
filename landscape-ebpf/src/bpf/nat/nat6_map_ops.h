#ifndef __LD_NAT6_MAP_OPS_H__
#define __LD_NAT6_MAP_OPS_H__

#include "nat/nat_common.h"
#include "nat/nat6_static.h"

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

static __always_inline bool
nat6_static_needs_prefix_replace(const struct static_nat6_mapping_value *value) {
    return value->lan_prefix[0] != 0 || value->lan_prefix[1] != 0 || value->lan_prefix[2] != 0 ||
           value->lan_prefix[3] != 0 || value->lan_prefix[4] != 0 || value->lan_prefix[5] != 0 ||
           value->lan_prefix[6] != 0 || value->lan_prefix[7] != 0;
}

static __always_inline struct static_nat6_mapping_value *
nat6_lookup_static(const struct nat6_mapping_key *local) {
    struct static_nat6_mapping_key key = {.l4_protocol = local->l4_protocol,
                                          .port = local->client_port};
    COPY_ADDR_FROM(key.ip_suffix, local->client_suffix);
    struct static_nat6_mapping_value *rule = bpf_map_lookup_elem(&nat6_static_map, &key);
    if (rule) return rule;
    key.port = 0;
    return bpf_map_lookup_elem(&nat6_static_map, &key);
}

#endif /* __LD_NAT6_MAP_OPS_H__ */
