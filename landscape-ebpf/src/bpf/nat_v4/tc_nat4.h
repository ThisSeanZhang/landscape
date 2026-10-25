/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TC_NAT4_H
#define LAND_NAT_TC_NAT4_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/mark.h"
#include "base/tc_act.h"
#include "reader/skb_ferry.h"
#include "nat_v4/nat4_ct_timer.h"
#include "nat_v4/tc_nat4_map.h"

static __always_inline int napt_create_dynamic_mapping(__u8 proto, __be32 internal_addr,
                                                       __be16 internal_port, __be32 remote_addr,
                                                       __be16 remote_port, __be16 external_port,
                                                       __u32 gen, __u8 allow_reuse) {
    struct napt_from_wan_value wan = {};
    struct napt_from_lan_value lan = {};
    struct napt_from_wan_value *slot = napt_wan_lookup(proto, external_port);

    if (!slot || slot->kind != NAPT_MAPPING_FREE) return -1;

    wan.internal_addr = internal_addr;
    wan.internal_port = internal_port;
    wan.kind = NAPT_MAPPING_DYNAMIC;
    wan.allow_reuse = allow_reuse;
    wan.trigger_addr = remote_addr;
    wan.trigger_port = remote_port;
    wan.generation = gen;
    wan.state_ref = napt_state_make(NAPT_WAN_STATE_ACTIVE, 0);

    if (napt_wan_publish(proto, external_port, &wan) != 0) return -1;

    lan.external_port = external_port;
    lan.kind = NAPT_MAPPING_DYNAMIC;
    lan.allow_reuse = allow_reuse;
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

    (void)napt_lan_delete_dynamic(internal_addr, internal_port, proto, external_port, gen);
    napt_wan_clear(proto, external_port);
    napt_queue_push(proto, external_port, gen);
}

#define NAPT_IP_MULTICAST_MASK bpf_ntohl(0xF0000000)
#define NAPT_IP_MULTICAST_BASE bpf_ntohl(0xE0000000)

static __always_inline int napt_is_broadcast_ip4(__be32 addr) {
    return addr == 0 || addr == 0xffffffff ||
           (addr & NAPT_IP_MULTICAST_MASK) == NAPT_IP_MULTICAST_BASE;
}

static __always_inline int napt_dynamic_remote_allowed(const struct napt_from_wan_value *mapping,
                                                       __be32 remote_addr, __be16 remote_port,
                                                       __u8 proto) {
    if (proto == IPV4_PROTO_ICMP || mapping->kind != NAPT_MAPPING_DYNAMIC) return 1;
    return mapping->allow_reuse ||
           (mapping->trigger_addr == remote_addr && mapping->trigger_port == remote_port);
}

static __always_inline int napt_dynamic_mapping_usable(const struct napt_from_wan_value *mapping,
                                                       __u32 gen) {
    return mapping && mapping->kind == NAPT_MAPPING_DYNAMIC && mapping->generation == gen &&
           napt_state_get(mapping->state_ref) == NAPT_WAN_STATE_ACTIVE &&
           napt_state_refs(mapping->state_ref) > 0;
}

#endif /* LAND_NAT_TC_NAT4_H */
