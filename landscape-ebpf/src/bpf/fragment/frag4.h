#ifndef __LD_FRAG4_H__
#define __LD_FRAG4_H__

#include "frag_common.h"
#include "../pkg_scanner.h"

static __always_inline int frag4_track(const struct packet_offset_info *offset,
                                       struct inet4_pair *ip_pair) {
#define BPF_LOG_TOPIC "frag4_track"
    if (likely(offset->fragment_type == FRAG_SINGLE)) {
        return TC_ACT_OK;
    }

    if (is_icmp_error_pkt(offset)) {
        return TC_ACT_SHOT;
    }

    int ret;
    struct frag_cache_key key = {0};
    key.l3proto = LANDSCAPE_IPV4_TYPE;
    key.l4proto = offset->l4_protocol;
    key.id = offset->fragment_id;

    key.saddr.ip = ip_pair->src_addr.addr;
    key.daddr.ip = ip_pair->dst_addr.addr;

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

#endif /* __LD_FRAG4_H__ */
