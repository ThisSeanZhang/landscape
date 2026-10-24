/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_NAT4_PACKET_H
#define LAND_NAT_TC_NAT4_PACKET_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "frag/frag.h"
#include "reader/skb_ferry.h"
#include "reader/tc_read_head4.h"
#include "nat_v4/tc_nat4.h"
#include "nat_v4/tc_nat4_rodata.h"

static __always_inline int napt_is_icmp_error(const struct skb_ferry_cb *cb) {
    return cb->icmp_inner_l4_offset != 0;
}

static __always_inline int napt_is_non_initial(const struct skb_ferry_cb *cb) {
    return cb->frag_code == LAND_NAT_FRAG_NON_INITIAL;
}

static __always_inline int napt_allows_create(const struct skb_ferry_cb *cb) {
    if (napt_is_icmp_error(cb) || napt_is_non_initial(cb)) return 0;
    if (cb->l4_protocol == IPV4_PROTO_TCP) return cb->tcp_phase == NAPT_TCP_PHASE_SYN;
    return cb->l4_protocol == IPV4_PROTO_UDP || cb->l4_protocol == IPV4_PROTO_ICMP;
}

static __always_inline int napt_lan_state(struct __sk_buff *skb, const struct skb_ferry_cb *cb,
                                          __be32 src_addr, __be32 dst_addr, __be32 *new_addr,
                                          __be16 *new_port) {
    __u8 proto = cb->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = napt_is_icmp_error(cb);
    int non_initial = napt_is_non_initial(cb);
    int allow_create = napt_allows_create(cb);
    __be16 internal_port = cb->sport;
    __be16 remote_port = icmp ? 0 : cb->dport;
    __be16 external_port = 0;
    __u32 gen = 0;
    __u8 kind = NAPT_MAPPING_FREE;
    int mapping_new = 0;

    struct napt_from_lan_value *lan = napt_lan_lookup(src_addr, internal_port, proto);

    if (lan) {
        external_port = lan->external_port;
        gen = lan->generation;
        kind = lan->kind;
    } else {
        if (!allow_create || !cb->ports_valid) return TC_ACT_SHOT;
        if (napt_queue_pop(proto, &external_port, &gen) != 0) return TC_ACT_SHOT;
        if (napt_create_dynamic_mapping(proto, src_addr, internal_port, dst_addr, remote_port,
                                        external_port, gen) != 0) {
            napt_queue_push(proto, external_port, gen);
            return TC_ACT_SHOT;
        }
        kind = NAPT_MAPPING_DYNAMIC;
        mapping_new = 1;
    }

    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);
    if (!mapping) {
        if (mapping_new)
            napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
        return TC_ACT_SHOT;
    }

    if (kind == NAPT_MAPPING_STATIC) {
        if (mapping->kind != NAPT_MAPPING_STATIC) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return TC_ACT_SHOT;
        }
    } else if (mapping->kind != NAPT_MAPPING_DYNAMIC || mapping->generation != gen ||
               napt_state_get(mapping->state_ref) != NAPT_WAN_STATE_ACTIVE ||
               (!mapping_new && napt_state_refs(mapping->state_ref) == 0)) {
        if (mapping_new)
            napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
        return TC_ACT_SHOT;
    }

    struct napt_ct_key key = {};
    napt_ct_key_init(&key, src_addr, internal_port, dst_addr, remote_port, proto);

    struct napt_ct_value *ct = 0;
    if (napt_ct_resolve(&key, mapping, &ct) != 0) ct = 0;

    if (!ct) {
        if (!allow_create) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return TC_ACT_SHOT;
        }

        ct = napt_ct_create(skb, &key, external_port, gen, kind == NAPT_MAPPING_STATIC,
                            NAPT_GRESS_LAN, mapping);
        if (!ct) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return TC_ACT_SHOT;
        }
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance(cb, NAPT_GRESS_LAN, ct) != TC_ACT_OK) return TC_ACT_SHOT;
        napt_metric_accumulate(skb, NAPT_GRESS_LAN, ct);
    }

    *new_addr = land_nat_external_addr;
    *new_port = external_port;
    return TC_ACT_OK;
}

static __always_inline int napt_wan_state(struct __sk_buff *skb, const struct skb_ferry_cb *cb,
                                          __be32 src_addr, __be32 *new_addr, __be16 *new_port) {
    __u8 proto = cb->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = napt_is_icmp_error(cb);
    int non_initial = napt_is_non_initial(cb);
    int allow_create = napt_allows_create(cb);
    __be16 external_port = icmp ? cb->sport : cb->dport;
    __be16 remote_port = icmp ? 0 : cb->sport;
    __u32 gen = 0;
    int is_static;

    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);
    if (!mapping || (mapping->kind != NAPT_MAPPING_DYNAMIC && mapping->kind != NAPT_MAPPING_STATIC))
        return TC_ACT_SHOT;

    if (mapping->kind == NAPT_MAPPING_STATIC) {
        is_static = 1;
    } else {
        gen = mapping->generation;
        if (!napt_dynamic_mapping_usable(mapping, gen)) return TC_ACT_SHOT;
        is_static = 0;
    }

    struct napt_ct_key key = {};
    napt_ct_key_init(&key, mapping->internal_addr, mapping->internal_port, src_addr, remote_port,
                     proto);

    struct napt_ct_value *ct = 0;
    if (napt_ct_resolve(&key, mapping, &ct) != 0) ct = 0;

    if (!ct) {
        if (!allow_create || !cb->ports_valid) return TC_ACT_SHOT;

        ct = napt_ct_create(skb, &key, external_port, gen, is_static, NAPT_GRESS_WAN, mapping);
        if (!ct) return TC_ACT_SHOT;
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance(cb, NAPT_GRESS_WAN, ct) != TC_ACT_OK) return TC_ACT_SHOT;
        napt_metric_accumulate(skb, NAPT_GRESS_WAN, ct);
    }

    *new_addr = mapping->internal_addr;
    *new_port = mapping->internal_port;
    return TC_ACT_OK;
}

#endif /* LAND_NAT_TC_NAT4_PACKET_H */
