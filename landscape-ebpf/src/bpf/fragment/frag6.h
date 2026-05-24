#ifndef __LD_FRAG6_H__
#define __LD_FRAG6_H__

#include "frag_common.h"
#include "../pkg_scanner.h"

static __always_inline int frag6_track(const struct packet_offset_info *offset,
                                       struct inet_pair *ip_pair) {
#define BPF_LOG_TOPIC "frag6_track"
    if (likely(offset->fragment_type == FRAG_SINGLE)) {
        return TC_ACT_OK;
    }

    if (is_icmp_error_pkt(offset)) {
        return TC_ACT_SHOT;
    }

    int ret;
    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV6_TYPE;
    key.l4proto = offset->l4_protocol;
    key.id = offset->fragment_id;

    COPY_ADDR_FROM(key.saddr.all, ip_pair->src_addr.all);
    COPY_ADDR_FROM(key.daddr.all, ip_pair->dst_addr.all);

    struct frag_cache_value *value;
    if (unlikely(offset->fragment_type == FRAG_FIRST)) {
        struct frag_cache_value value_new;
        value_new.dport = ip_pair->dst_port;
        value_new.sport = ip_pair->src_port;

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
            ld_bpf_log("fragmentation session of this packet was not tracked");
            return TC_ACT_SHOT;
        }
        ip_pair->src_port = value->sport;
        ip_pair->dst_port = value->dport;
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_FRAG6_H__ */
