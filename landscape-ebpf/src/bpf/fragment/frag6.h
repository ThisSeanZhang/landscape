#ifndef __LD_FRAG6_H__
#define __LD_FRAG6_H__

#include "frag_common.h"
#include "../scanner/scan_types.h"

static __always_inline int frag6_track(const struct scan_ipv6_idx *idx,
                                       const struct in6_addr *saddr, const struct in6_addr *daddr,
                                       __be16 *sport, __be16 *dport) {
    if (likely(idx->fragment_type == FRAG_SINGLE)) {
        return TC_ACT_OK;
    }

    if (idx->icmp_error_l3_offset > 0 && idx->icmp_error_inner_l4_offset > 0) {
        return TC_ACT_SHOT;
    }

    int ret;
    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV6_TYPE;
    key.l4proto = idx->l4_protocol;
    key.id = idx->fragment_id;

    COPY_ADDR_FROM(key.saddr.all, saddr->in6_u.u6_addr32);
    COPY_ADDR_FROM(key.daddr.all, daddr->in6_u.u6_addr32);

    struct frag_cache_value *value;
    if (unlikely(idx->fragment_type == FRAG_FIRST)) {
        struct frag_cache_value value_new = {
            .sport = *sport,
            .dport = *dport,
        };
        ret = bpf_map_update_elem(&frag_cache, &key, &value_new, BPF_ANY);
        if (ret) {
            return TC_ACT_SHOT;
        }
        value = (struct frag_cache_value *)bpf_map_lookup_elem(&frag_cache, &key);
        if (!value) {
            return TC_ACT_SHOT;
        }
    } else {
        value = (struct frag_cache_value *)bpf_map_lookup_elem(&frag_cache, &key);
        if (!value) {
            return TC_ACT_SHOT;
        }
        *sport = value->sport;
        *dport = value->dport;
    }

    return TC_ACT_OK;
}

#endif /* __LD_FRAG6_H__ */
