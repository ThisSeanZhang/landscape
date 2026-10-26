/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_NAT4_PACKET_H
#define LAND_NAT_TC_NAT4_PACKET_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv4.h"
#include "frag/frag.h"
#include "reader/tc_nat_view.h"
#include "reader/tc_nat_read4.h"
#include "nat_v4/tc_nat4.h"
#include "nat_v4/tc_nat4_rodata.h"

static __always_inline int napt_is_icmp_error(const struct tc_nat_view *view) {
    return view->icmp_inner_l4_offset != 0;
}

static __always_inline int napt_is_non_initial(const struct tc_nat_view *view) {
    return view->frag_code == LAND_NAT_FRAG_NON_INITIAL;
}

static __always_inline int napt_allows_create(const struct tc_nat_view *view) {
    if (napt_is_icmp_error(view) || napt_is_non_initial(view)) return 0;
    if (view->l4_protocol == IPV4_PROTO_TCP) return view->tcp_phase == NAPT_TCP_PHASE_SYN;
    return view->l4_protocol == IPV4_PROTO_UDP || view->l4_protocol == IPV4_PROTO_ICMP;
}

static __always_inline int napt_lan_state(struct __sk_buff *skb, const struct tc_nat_view *view,
                                          __be32 src_addr, __be32 dst_addr, __be32 *new_addr,
                                          __be16 *new_port) {
    __u8 proto = view->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = napt_is_icmp_error(view);
    int non_initial = napt_is_non_initial(view);
    int allow_create = napt_allows_create(view);
    __be16 internal_port = view->sport;
    __be16 remote_port = icmp ? 0 : view->dport;
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
        if (!allow_create || !view->ports_valid) return TC_ACT_SHOT;
        __u8 allow_reuse = get_flow_allow_reuse_port(skb_mark(skb)) ? 1 : 0;
        if (napt_queue_pop(proto, &external_port, &gen) != 0) return TC_ACT_SHOT;
        if (napt_create_dynamic_mapping(proto, src_addr, internal_port, dst_addr, remote_port,
                                        external_port, gen, allow_reuse) != 0) {
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

    if (!mapping_new && !napt_dynamic_remote_allowed(mapping, dst_addr, remote_port, proto))
        return TC_ACT_SHOT;

    if (!mapping_new && mapping->kind == NAPT_MAPPING_DYNAMIC &&
        mapping->trigger_addr == dst_addr && mapping->trigger_port == remote_port) {
        __u8 allow_reuse = get_flow_allow_reuse_port(skb_mark(skb)) ? 1 : 0;
        mapping->allow_reuse = allow_reuse;
        if (lan && lan->kind == NAPT_MAPPING_DYNAMIC) lan->allow_reuse = allow_reuse;
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

        ct = napt_ct_create(skb->ifindex, skb_mark(skb), &key, external_port, gen,
                            kind == NAPT_MAPPING_STATIC, NAPT_GRESS_LAN, mapping);
        if (!ct) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return TC_ACT_SHOT;
        }
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance(view, NAPT_GRESS_LAN, ct) != TC_ACT_OK) return TC_ACT_SHOT;
        napt_metric_accumulate(skb, NAPT_GRESS_LAN, ct);
    }

    *new_addr = land_nat_external_addr;
    *new_port = external_port;
    return TC_ACT_OK;
}

static __always_inline int napt_wan_state(struct __sk_buff *skb, const struct tc_nat_view *view,
                                          __be32 src_addr, __be32 dst_addr, __be32 *new_addr,
                                          __be16 *new_port) {
    __u8 proto = view->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = napt_is_icmp_error(view);
    int non_initial = napt_is_non_initial(view);
    int allow_create = napt_allows_create(view);
    __be16 external_port = icmp ? view->sport : view->dport;
    __be16 remote_port = icmp ? 0 : view->sport;
    __u32 gen = 0;
    int is_static;

    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);
    if (!mapping || (mapping->kind != NAPT_MAPPING_DYNAMIC && mapping->kind != NAPT_MAPPING_STATIC))
        return TC_ACT_SHOT;

    __be32 target_addr;
    if (mapping->kind == NAPT_MAPPING_STATIC) {
        is_static = 1;
        target_addr = mapping->internal_addr;
        if (target_addr == 0) target_addr = dst_addr;
        skb_set_mark(skb, replace_cache_mask(skb_mark(skb), INGRESS_STATIC_MARK));
    } else {
        gen = mapping->generation;
        if (!napt_dynamic_mapping_usable(mapping, gen)) return TC_ACT_SHOT;
        if (!napt_dynamic_remote_allowed(mapping, src_addr, remote_port, proto)) return TC_ACT_SHOT;
        is_static = 0;
        target_addr = mapping->internal_addr;
    }

    struct napt_ct_key key = {};
    napt_ct_key_init(&key, target_addr, mapping->internal_port, src_addr, remote_port, proto);

    struct napt_ct_value *ct = 0;
    if (napt_ct_resolve(&key, mapping, &ct) != 0) ct = 0;

    if (!ct) {
        if (!allow_create || !view->ports_valid) return TC_ACT_SHOT;

        ct = napt_ct_create(skb->ifindex, skb_mark(skb), &key, external_port, gen, is_static,
                            NAPT_GRESS_WAN, mapping);
        if (!ct) return TC_ACT_SHOT;
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance(view, NAPT_GRESS_WAN, ct) != TC_ACT_OK) return TC_ACT_SHOT;
        napt_metric_accumulate(skb, NAPT_GRESS_WAN, ct);
    }

    *new_addr = target_addr;
    *new_port = mapping->internal_port;
    return TC_ACT_OK;
}

#endif /* LAND_NAT_TC_NAT4_PACKET_H */
