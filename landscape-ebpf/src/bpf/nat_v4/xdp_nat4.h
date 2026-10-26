/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_XDP_NAT4_V4_H
#define LAND_NAT_XDP_NAT4_V4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "frag/frag.h"
#include "nat_v4/nat4_ct_timer.h"
#include "nat_v4/nat4_metric.h"
#include "nat_v4/tc_nat4.h"
#include "nat_v4/tc_nat4_map.h"
#include "nat_v4/tc_nat4_rodata.h"
#include "reader/xdp_nat_view.h"

#define NAPT_XDP_OK 0
#define NAPT_XDP_DROP 1

static __always_inline bool xdp_nat4_supported_protocol(__u8 proto) {
    return proto == IPV4_PROTO_TCP || proto == IPV4_PROTO_UDP || proto == IPV4_PROTO_ICMP;
}

static __always_inline int xdp_napt_lan_state(const struct xdp_nat_view *view, __be32 src_addr,
                                              __be32 dst_addr, u32 ifindex, u32 mark, u64 bytes,
                                              __be32 *new_addr, __be16 *new_port) {
    if (!view->ports_valid) return NAPT_XDP_DROP;

    u8 proto = view->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = view->icmp_inner_l4_offset != 0;
    int non_initial = view->frag_code == LAND_NAT_FRAG_NON_INITIAL;
    __u8 tcp_phase = view->tcp_phase;
    int allow_create = !icmp_error && !non_initial &&
                       (proto == IPV4_PROTO_TCP ? tcp_phase == NAPT_TCP_PHASE_SYN
                                                : (proto == IPV4_PROTO_UDP || icmp));
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
        if (!allow_create) return NAPT_XDP_DROP;
        __u8 allow_reuse = get_flow_allow_reuse_port(mark) ? 1 : 0;
        if (napt_queue_pop(proto, &external_port, &gen) != 0) return NAPT_XDP_DROP;
        if (napt_create_dynamic_mapping(proto, src_addr, internal_port, dst_addr, remote_port,
                                        external_port, gen, allow_reuse) != 0) {
            napt_queue_push(proto, external_port, gen);
            return NAPT_XDP_DROP;
        }
        kind = NAPT_MAPPING_DYNAMIC;
        mapping_new = 1;
    }

    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);
    if (!mapping) {
        if (mapping_new)
            napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
        return NAPT_XDP_DROP;
    }

    if (kind == NAPT_MAPPING_STATIC) {
        if (mapping->kind != NAPT_MAPPING_STATIC) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return NAPT_XDP_DROP;
        }
    } else if (mapping->kind != NAPT_MAPPING_DYNAMIC || mapping->generation != gen ||
               napt_state_get(mapping->state_ref) != NAPT_WAN_STATE_ACTIVE ||
               (!mapping_new && napt_state_refs(mapping->state_ref) == 0)) {
        if (mapping_new)
            napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
        return NAPT_XDP_DROP;
    }

    if (!mapping_new && !napt_dynamic_remote_allowed(mapping, dst_addr, remote_port, proto))
        return NAPT_XDP_DROP;

    if (!mapping_new && mapping->kind == NAPT_MAPPING_DYNAMIC &&
        mapping->trigger_addr == dst_addr && mapping->trigger_port == remote_port) {
        __u8 allow_reuse = get_flow_allow_reuse_port(mark) ? 1 : 0;
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
            return NAPT_XDP_DROP;
        }

        ct = napt_ct_create(ifindex, mark, &key, external_port, gen, kind == NAPT_MAPPING_STATIC,
                            NAPT_GRESS_LAN, mapping);
        if (!ct) {
            if (mapping_new)
                napt_rollback_new_mapping(proto, src_addr, internal_port, external_port, gen);
            return NAPT_XDP_DROP;
        }
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance_pkt(proto, tcp_phase, NAPT_GRESS_LAN, ct) != TC_ACT_OK)
            return NAPT_XDP_DROP;
        napt_metric_accumulate_bytes(bytes, NAPT_GRESS_LAN, ct);
    }

    *new_addr = land_nat_external_addr;
    *new_port = external_port;
    return NAPT_XDP_OK;
}

static __always_inline int xdp_napt_wan_state(const struct xdp_nat_view *view, __be32 src_addr,
                                              __be32 dst_addr, u32 ifindex, u32 *mark, u64 bytes,
                                              __be32 *new_addr, __be16 *new_port, bool *is_static) {
    if (!view->ports_valid) return NAPT_XDP_DROP;

    u8 proto = view->l4_protocol;
    int icmp = proto == IPV4_PROTO_ICMP;
    int icmp_error = view->icmp_inner_l4_offset != 0;
    int non_initial = view->frag_code == LAND_NAT_FRAG_NON_INITIAL;
    __u8 tcp_phase = view->tcp_phase;
    int allow_create = !icmp_error && !non_initial &&
                       (proto == IPV4_PROTO_TCP ? tcp_phase == NAPT_TCP_PHASE_SYN
                                                : (proto == IPV4_PROTO_UDP || icmp));
    __be16 external_port = icmp ? view->sport : view->dport;
    __be16 remote_port = icmp ? 0 : view->sport;
    __u32 gen = 0;
    int static_mapping;

    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);
    if (!mapping || (mapping->kind != NAPT_MAPPING_DYNAMIC && mapping->kind != NAPT_MAPPING_STATIC))
        return NAPT_XDP_DROP;

    __be32 target_addr;
    if (mapping->kind == NAPT_MAPPING_STATIC) {
        static_mapping = 1;
        target_addr = mapping->internal_addr;
        if (target_addr == 0) target_addr = dst_addr;
        *mark = replace_cache_mask(*mark, INGRESS_STATIC_MARK);
    } else {
        gen = mapping->generation;
        if (!napt_dynamic_mapping_usable(mapping, gen)) return NAPT_XDP_DROP;
        if (!napt_dynamic_remote_allowed(mapping, src_addr, remote_port, proto))
            return NAPT_XDP_DROP;
        static_mapping = 0;
        target_addr = mapping->internal_addr;
    }

    struct napt_ct_key key = {};
    napt_ct_key_init(&key, target_addr, mapping->internal_port, src_addr, remote_port, proto);

    struct napt_ct_value *ct = 0;
    if (napt_ct_resolve(&key, mapping, &ct) != 0) ct = 0;

    if (!ct) {
        if (!allow_create) return NAPT_XDP_DROP;

        ct = napt_ct_create(ifindex, *mark, &key, external_port, gen, static_mapping,
                            NAPT_GRESS_WAN, mapping);
        if (!ct) return NAPT_XDP_DROP;
    }

    if (!icmp_error && !non_initial) {
        if (napt_ct_advance_pkt(proto, tcp_phase, NAPT_GRESS_WAN, ct) != TC_ACT_OK)
            return NAPT_XDP_DROP;
        napt_metric_accumulate_bytes(bytes, NAPT_GRESS_WAN, ct);
    }

    *new_addr = target_addr;
    *new_port = mapping->internal_port;
    *is_static = static_mapping;
    return NAPT_XDP_OK;
}

#endif /* LAND_NAT_XDP_NAT4_V4_H */
