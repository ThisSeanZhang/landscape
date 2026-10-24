/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_NAT4_H
#define LAND_NAT_TC_NAT4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/tc_act.h"
#include "reader/skb_ferry.h"
#include "nat_v4/nat4_ct_timer.h"
#include "nat_v4/tc_nat4_map.h"

enum napt_gress {
    NAPT_GRESS_LAN = 0,
    NAPT_GRESS_WAN = 1,
};

static __always_inline int napt_create_dynamic_mapping(__u8 proto, __be32 internal_addr,
                                                       __be16 internal_port, __be32 remote_addr,
                                                       __be16 remote_port, __be16 external_port,
                                                       __u32 gen) {
    struct napt_from_wan_value wan = {};
    struct napt_from_lan_value lan = {};
    struct napt_from_wan_value *slot = napt_wan_lookup(proto, external_port);

    if (!slot || slot->kind != NAPT_MAPPING_FREE) return -1;

    wan.internal_addr = internal_addr;
    wan.internal_port = internal_port;
    wan.kind = NAPT_MAPPING_DYNAMIC;
    wan.allow_reuse = 1;
    wan.trigger_addr = remote_addr;
    wan.trigger_port = remote_port;
    wan.generation = gen;
    wan.state_ref = napt_state_make(NAPT_WAN_STATE_ACTIVE, 0);

    if (napt_wan_publish(proto, external_port, &wan) != 0) return -1;

    lan.external_port = external_port;
    lan.kind = NAPT_MAPPING_DYNAMIC;
    lan.allow_reuse = 1;
    lan.generation = gen;
    lan.trigger_addr = remote_addr;
    lan.trigger_port = remote_port;

    if (napt_lan_insert(internal_addr, internal_port, proto, &lan) != 0) {
        napt_wan_clear(proto, external_port);
        return -1;
    }

    return 0;
}

static __always_inline void napt_rollback_new_mapping(__u8 proto, __be32 internal_addr,
                                                      __be16 internal_port, __be16 external_port,
                                                      __u32 gen) {
    struct napt_from_wan_value *mapping = napt_wan_lookup(proto, external_port);

    if (!mapping || mapping->kind != NAPT_MAPPING_DYNAMIC || mapping->generation != gen ||
        napt_state_get(mapping->state_ref) != NAPT_WAN_STATE_ACTIVE ||
        napt_state_refs(mapping->state_ref) != 0)
        return;

    napt_lan_delete_dynamic(internal_addr, internal_port, proto, external_port, gen);
    napt_wan_clear(proto, external_port);
    napt_queue_push(proto, external_port, gen);
}

static __always_inline struct napt_ct_value *
napt_ct_create(struct __sk_buff *skb, const struct napt_ct_key *key, __be16 external_port,
               __u32 gen, int is_static, u8 gress, struct napt_from_wan_value *mapping) {
    struct napt_ct_value initial = {};
    struct napt_ct_value *value;

    initial.external_port = external_port;
    initial.from_wan_gen = gen;
    initial.is_static = is_static ? 1 : 0;
    initial.status = is_static ? NAPT_CT_INIT : NAPT_CT_PENDING_REF;
    initial.client_status = NAPT_TCP_STATE_INIT;
    initial.server_status = NAPT_TCP_STATE_INIT;
    initial.create_time = bpf_ktime_get_tai_ns();
    initial.cpu_id = bpf_get_smp_processor_id();
    initial.ifindex = skb ? skb->ifindex : 0;
    initial.gress = gress;
    initial.flow_id = 0;

    value = napt_ct_insert(key, &initial);
    if (!value) return 0;

    if (!is_static) {
        if (!mapping || napt_wan_ref_inc(mapping) != 0) {
            bpf_map_delete_elem(&napt_ct, key);
            return 0;
        }
        value->status = NAPT_CT_INIT;
    }

    return value;
}

static __always_inline int napt_dynamic_mapping_usable(const struct napt_from_wan_value *mapping,
                                                       __u32 gen) {
    return mapping && mapping->kind == NAPT_MAPPING_DYNAMIC && mapping->generation == gen &&
           napt_state_get(mapping->state_ref) == NAPT_WAN_STATE_ACTIVE &&
           napt_state_refs(mapping->state_ref) > 0;
}

#endif /* LAND_NAT_TC_NAT4_H */
