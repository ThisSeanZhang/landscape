#ifndef __LD_XDP_FRAG4_H__
#define __LD_XDP_FRAG4_H__

#include "frag_common.h"
#include "../scanner/xdp_scanner4.h"

static __always_inline int xdp_frag4_track(const struct scan_ipv4_idx *idx, __be32 saddr,
                                           __be32 daddr, __be16 *sport, __be16 *dport) {
    if (likely(idx->fragment_type == FRAG_SINGLE)) {
        return XDP_PASS;
    }

    if (idx->icmp_error_l3_offset > 0 && idx->icmp_error_inner_l4_offset > 0) {
        return XDP_DROP;
    }

    int ret;
    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV4_TYPE;
    key.l4proto = idx->l4_protocol;
    key.id = idx->fragment_id;
    key.saddr.ip = saddr;
    key.daddr.ip = daddr;

    struct frag_cache_value *value;
    if (unlikely(idx->fragment_type == FRAG_FIRST)) {
        struct frag_cache_value value_new = {
            .sport = *sport,
            .dport = *dport,
        };
        ret = bpf_map_update_elem(&frag_cache, &key, &value_new, BPF_ANY);
        if (ret) {
            return XDP_DROP;
        }
        value = (struct frag_cache_value *)bpf_map_lookup_elem(&frag_cache, &key);
        if (!value) {
            return XDP_DROP;
        }
    } else {
        value = (struct frag_cache_value *)bpf_map_lookup_elem(&frag_cache, &key);
        if (!value) {
            return XDP_DROP;
        }
        *sport = value->sport;
        *dport = value->dport;
    }

    return XDP_PASS;
}

#endif /* __LD_XDP_FRAG4_H__ */
