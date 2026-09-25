#ifndef LD_NAT4_V3_H
#define LD_NAT4_V3_H

#include <vmlinux.h>

#include "../landscape_log.h"
#include "../chain/tc_cb.h"
#include "nat_common.h"
#include "nat_metric.h"
#include "nat4_map_ops.h"
#include "nat4_ct_timer.h"
#include "../land_wan_ip.h"
#include "../einat_nat4.h"

static __always_inline void nat_metric_accumulate(struct __sk_buff *skb, bool ingress,
                                                  struct nat4_timer_value_v3 *value) {
    u64 bytes = skb->len;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline int nat4_ct_create(struct __sk_buff *skb, u32 ifindex,
                                          const struct nat4_timer_key *ct_key,
                                          const struct inet4_addr *client_addr, __be16 client_port,
                                          u8 gress, struct nat4_mapping_value_v3 *dyn_ingress,
                                          struct nat4_timer_value_v3 **timer_value_) {
    bool track_dynamic_ref = dyn_ingress != NULL;
    u16 generation_snapshot = track_dynamic_ref ? dyn_ingress->generation : 0;

    struct nat4_timer_value_v3 new_value = {0};
    new_value.client_port = client_port;
    new_value.client_status = CT_INIT;
    new_value.server_status = CT_INIT;
    new_value.gress = gress;
    new_value.client_addr = *client_addr;
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    new_value.generation_snapshot = generation_snapshot;
    new_value.is_static = dyn_ingress == NULL ? 1 : 0;
    new_value.status = track_dynamic_ref ? TIMER_PENDING_REF : TIMER_INIT;

    struct nat4_timer_value_v3 *timer_value = nat4_insert_ct(ct_key, &new_value);
    if (!timer_value) {
        return -1;
    }

    if (track_dynamic_ref) {
        if (nat4_state_try_inc(dyn_ingress) != 0) {
            bpf_map_delete_elem(&nat4_timer_map, ct_key);
            return -1;
        }
        timer_value->status = TIMER_INIT;
    }

    *timer_value_ = timer_value;
    return 0;
}

static __always_inline int nat4_dyn_egress_lookup_and_check(
    struct __sk_buff *skb, u32 ifindex, u8 ip_protocol, bool allow_create_mapping,
    const struct inet4_pair *pkt_ip_pair, struct nat4_egress_result *result,
    struct nat4_mapping_value_v3 **dyn_ingress_out, struct nat4_port_queue_value_v3 *alloc_item) {
    *dyn_ingress_out = NULL;
    result->is_created = 0;

    struct nat4_mapping_key egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->src_port,
        .from_addr = pkt_ip_pair->src_addr.addr,
    };

    struct nat4_egress_mapping_value_v3 *egress_value =
        bpf_map_lookup_elem(&nat4_egress_dyn_map, &egress_key);

    if (egress_value) {
        struct nat4_mapping_key ingress_key = {
            .gress = NAT_MAPPING_INGRESS,
            .l4proto = ip_protocol,
            .from_addr = egress_value->addr,
            .from_port = egress_value->port,
        };
        struct nat4_mapping_value_v3 *ingress_value =
            bpf_map_lookup_elem(&nat4_ingress_dyn_map, &ingress_key);
        if (!ingress_value || ingress_value->addr != pkt_ip_pair->src_addr.addr ||
            ingress_value->port != pkt_ip_pair->src_port) {
            bpf_map_delete_elem(&nat4_egress_dyn_map, &egress_key);
        } else {
            result->nat_addr = egress_value->addr;
            result->nat_port = egress_value->port;
            *dyn_ingress_out = ingress_value;

            bool is_ancestor = pkt_ip_pair->dst_addr.addr == egress_value->trigger_addr &&
                               pkt_ip_pair->dst_port == egress_value->trigger_port;
            if (egress_value->is_allow_reuse == 0 && ip_protocol != IPPROTO_ICMP) {
                if (!is_ancestor) return TC_ACT_SHOT;
            }
            if (is_ancestor) {
                u8 allow = get_flow_allow_reuse_port(skb->mark) ? 1 : 0;
                egress_value->is_allow_reuse = allow;
                ingress_value->is_allow_reuse = allow;
            }
            return TC_ACT_OK;
        }
    }

    if (!allow_create_mapping) {
        return TC_ACT_SHOT;
    }

    struct wan_ip_info_key wan_search_key = {
        .chain_id = tc_cb_chain_id(skb),
        .l3_protocol = LANDSCAPE_IPV4_TYPE,
    };
    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (!wan_ip_info) {
        return TC_ACT_SHOT;
    }

    if (nat4_alloc_port(ip_protocol, alloc_item) != 0) {
        return TC_ACT_SHOT;
    }

    u16 generation = alloc_item->last_generation + 1;
    struct nat4_egress_mapping_value_v3 new_value = {
        .addr = wan_ip_info->addr.ip,
        .trigger_addr = pkt_ip_pair->dst_addr.addr,
        .port = alloc_item->port,
        .trigger_port = pkt_ip_pair->dst_port,
        .is_allow_reuse = get_flow_allow_reuse_port(skb->mark) ? 1 : 0,
    };

    struct nat4_mapping_value_v3 *ingress_value = NULL;
    struct nat4_egress_mapping_value_v3 *egress_out =
        nat4_insert_mappings(&egress_key, &new_value, generation, &ingress_value);
    if (!egress_out || !ingress_value) {
        (void)nat4_queue_push(ip_protocol, alloc_item);
        return TC_ACT_SHOT;
    }

    result->is_created = 1;
    result->nat_addr = wan_ip_info->addr.ip;
    result->nat_port = alloc_item->port;
    *dyn_ingress_out = ingress_value;
    return TC_ACT_OK;
}

static __always_inline int nat4_st_egress_lookup(u32 chain_id, u8 ip_protocol,
                                                 const struct inet4_pair *pkt_ip_pair,
                                                 struct nat4_egress_result *result) {
    struct nat4_mapping_key static_egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->src_port,
        .from_addr = pkt_ip_pair->src_addr.addr,
    };
    struct nat4_static_value *static_egress =
        bpf_map_lookup_elem(&nat4_static_map, &static_egress_key);
    if (!static_egress && pkt_ip_pair->src_addr.addr != 0) {
        static_egress_key.from_addr = 0;
        static_egress = bpf_map_lookup_elem(&nat4_static_map, &static_egress_key);
    }
    if (!static_egress) return TC_ACT_SHOT;

    struct nat4_static_value *st_ingress =
        nat4_lookup_static_ingress(ip_protocol, static_egress->port);
    if (!st_ingress) return TC_ACT_SHOT;

    struct wan_ip_info_key wan_search_key = {
        .chain_id = chain_id,
        .l3_protocol = LANDSCAPE_IPV4_TYPE,
    };
    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (!wan_ip_info) return TC_ACT_SHOT;

    result->nat_addr = wan_ip_info->addr.ip;
    result->nat_port = static_egress->port;
    return TC_ACT_OK;
}

static __always_inline int
nat4_dyn_ingress_lookup_and_check(u8 ip_protocol, const struct inet4_pair *pkt_ip_pair,
                                  struct nat4_lan_result *result,
                                  struct nat4_mapping_value_v3 **dyn_ingress_out) {
    *dyn_ingress_out = NULL;

    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->dst_port,
        .from_addr = pkt_ip_pair->dst_addr.addr,
    };

    struct nat4_mapping_value_v3 *dynamic_value =
        bpf_map_lookup_elem(&nat4_ingress_dyn_map, &ingress_key);
    if (!dynamic_value) return TC_ACT_SHOT;

    if (dynamic_value->is_allow_reuse == 0 && ip_protocol != IPPROTO_ICMP) {
        if (pkt_ip_pair->src_addr.addr != dynamic_value->trigger_addr ||
            pkt_ip_pair->src_port != dynamic_value->trigger_port)
            return TC_ACT_SHOT;
    }

    result->lan_addr = dynamic_value->addr;
    result->lan_port = dynamic_value->port;
    *dyn_ingress_out = dynamic_value;
    return TC_ACT_OK;
}

static __always_inline int nat4_st_ingress_lookup(u8 ip_protocol,
                                                  const struct inet4_pair *pkt_ip_pair,
                                                  struct nat4_lan_result *result) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->dst_port,
        .from_addr = 0,
    };

    struct nat4_static_value *st_value = bpf_map_lookup_elem(&nat4_static_map, &ingress_key);
    if (!st_value) return TC_ACT_SHOT;

    result->lan_addr = st_value->addr;
    result->lan_port = st_value->port;
    return TC_ACT_OK;
}

#endif /* LD_NAT4_V3_H */
