#ifndef __LD_XDP_NAT4_H__
#define __LD_XDP_NAT4_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "../land_nat_common.h"
#include "../land_nat4_v3.h"
#include "../land_wan_ip.h"
#include "../fragment/frag_common.h"
#include "../fragment/xdp_frag4.h"
#include "nat_maps.h"
#include "nat_v3_maps.h"

static __always_inline int xdp_read_nat_info4(void *data, void *data_end, u16 l4_offset,
                                              u8 l4_protocol, struct inet4_pair *pair,
                                              u8 fragment_type) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return -1;

    pair->src_addr.addr = iph->saddr;
    pair->dst_addr.addr = iph->daddr;

    if (fragment_type >= FRAG_MIDDLE) return 0;

    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else {
        return 0;
    }

    return 0;
}

static __always_inline int xdp_nat4_static_egress_lookup(u8 l4proto, const struct inet4_pair *pair,
                                                         struct nat4_mapping_value_v3 **egress,
                                                         struct nat4_mapping_value_v3 **ingress) {
    struct nat_mapping_key_v4 egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = l4proto,
        .from_port = pair->src_port,
        .from_addr = pair->src_addr.addr,
    };

    struct nat4_mapping_value_v3 *static_egress = bpf_map_lookup_elem(&nat4_st_map, &egress_key);
    if (!static_egress && pair->src_addr.addr != 0) {
        egress_key.from_addr = 0;
        static_egress = bpf_map_lookup_elem(&nat4_st_map, &egress_key);
    }
    if (!static_egress) return -1;

    struct nat_mapping_key_v4 ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = l4proto,
        .from_port = static_egress->port,
        .from_addr = static_egress->addr,
    };
    struct nat4_mapping_value_v3 *static_ingress = bpf_map_lookup_elem(&nat4_st_map, &ingress_key);
    if (!static_ingress) {
        ingress_key.from_addr = 0;
        static_ingress = bpf_map_lookup_elem(&nat4_st_map, &ingress_key);
    }
    if (!static_ingress) return -1;

    *egress = static_egress;
    *ingress = static_ingress;
    return 0;
}

static __always_inline int xdp_nat4_static_ingress_lookup(u8 l4proto, const struct inet4_pair *pair,
                                                          struct nat4_mapping_value_v3 **ingress) {
    struct nat_mapping_key_v4 ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = l4proto,
        .from_port = pair->dst_port,
        .from_addr = pair->dst_addr.addr,
    };

    struct nat4_mapping_value_v3 *static_ingress = bpf_map_lookup_elem(&nat4_st_map, &ingress_key);
    if (!static_ingress) {
        ingress_key.from_addr = 0;
        static_ingress = bpf_map_lookup_elem(&nat4_st_map, &ingress_key);
    }
    if (!static_ingress) return -1;

    *ingress = static_ingress;
    return 0;
}

static __always_inline int xdp_csum_update_l4(void *data, void *data_end, u16 l4_offset,
                                              u8 l4_protocol, __be16 old_port, __be16 new_port,
                                              __be32 old_addr, __be32 new_addr,
                                              bool is_icmpx_error) {
    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;

        __s64 d = bpf_csum_diff(&old_port, sizeof(old_port), &new_port, sizeof(new_port), 0);
        d = bpf_csum_diff(&old_addr, sizeof(old_addr), &new_addr, sizeof(new_addr), d);
        tcph->check = bpf_csum_diff(0, 0, &tcph->check, sizeof(tcph->check), d);
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;

        if (udph->check != 0 || is_icmpx_error) {
            __s64 d = bpf_csum_diff(&old_port, sizeof(old_port), &new_port, sizeof(new_port), 0);
            d = bpf_csum_diff(&old_addr, sizeof(old_addr), &new_addr, sizeof(new_addr), d);
            udph->check = bpf_csum_diff(0, 0, &udph->check, sizeof(udph->check), d);
        }
    }

    return 0;
}

static __always_inline int xdp_modify_headers_v4(void *data, void *data_end, u16 l4_offset,
                                                 u8 l4_protocol, bool is_modify_source,
                                                 const struct nat_action_v4 *action,
                                                 bool is_icmpx_error, u16 icmp_err_l3_offset,
                                                 u16 icmp_err_l4_offset, u8 icmp_err_l4_proto) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return -1;

    __be32 old_addr = is_modify_source ? iph->saddr : iph->daddr;
    if (is_modify_source)
        iph->saddr = action->to_addr.addr;
    else
        iph->daddr = action->to_addr.addr;
    iph->check = bpf_csum_diff(&old_addr, sizeof(old_addr), &action->to_addr.addr,
                               sizeof(action->to_addr.addr), iph->check);

    if (l4_protocol == IPPROTO_ICMP) {
        if (is_icmpx_error) {
            struct iphdr *inner_ip = data + icmp_err_l3_offset;
            if ((void *)(inner_ip + 1) > data_end) return -1;

            __be32 inner_old_addr = is_modify_source ? inner_ip->daddr : inner_ip->saddr;
            if (is_modify_source)
                inner_ip->daddr = action->to_addr.addr;
            else
                inner_ip->saddr = action->to_addr.addr;
            inner_ip->check =
                bpf_csum_diff(&inner_old_addr, sizeof(inner_old_addr), &action->to_addr.addr,
                              sizeof(action->to_addr.addr), inner_ip->check);

            struct icmphdr *icmph = data + l4_offset;
            if ((void *)(icmph + 1) > data_end) return -1;
            icmph->checksum =
                bpf_csum_diff(&inner_old_addr, sizeof(inner_old_addr), &action->to_addr.addr,
                              sizeof(action->to_addr.addr), icmph->checksum);

            if (icmp_err_l4_offset != 0) {
                xdp_csum_update_l4(data, data_end, icmp_err_l4_offset, icmp_err_l4_proto,
                                   is_modify_source ? action->from_port : action->to_port,
                                   is_modify_source ? action->to_port : action->from_port, old_addr,
                                   action->to_addr.addr, true);
            }
        } else {
            struct icmphdr *icmph = data + l4_offset;
            if ((void *)(icmph + 1) > data_end) return -1;
            icmph->checksum =
                bpf_csum_diff(&icmph->un.echo.id, sizeof(icmph->un.echo.id), &action->to_port,
                              sizeof(action->to_port), icmph->checksum);
        }
        return 0;
    }

    if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;

        __be16 old_port = is_modify_source ? udph->source : udph->dest;
        if (is_modify_source)
            udph->source = action->to_port;
        else
            udph->dest = action->to_port;

        if (udph->check != 0) {
            __s64 d = bpf_csum_diff(&old_port, sizeof(old_port), &action->to_port,
                                    sizeof(action->to_port), 0);
            d = bpf_csum_diff(&old_addr, sizeof(old_addr), &action->to_addr.addr,
                              sizeof(action->to_addr.addr), d);
            udph->check = bpf_csum_diff(0, 0, &udph->check, sizeof(udph->check), d);
        }

        if (is_icmpx_error && icmp_err_l4_offset != 0) {
            xdp_csum_update_l4(data, data_end, icmp_err_l4_offset, icmp_err_l4_proto,
                               is_modify_source ? action->from_port : action->to_port,
                               is_modify_source ? action->to_port : action->from_port, old_addr,
                               action->to_addr.addr, true);
        }
        return 0;
    }

    struct tcphdr *tcph = data + l4_offset;
    if ((void *)(tcph + 1) > data_end) return -1;

    __be16 old_port = is_modify_source ? tcph->source : tcph->dest;
    if (is_modify_source)
        tcph->source = action->to_port;
    else
        tcph->dest = action->to_port;

    __s64 d =
        bpf_csum_diff(&old_port, sizeof(old_port), &action->to_port, sizeof(action->to_port), 0);
    d = bpf_csum_diff(&old_addr, sizeof(old_addr), &action->to_addr.addr,
                      sizeof(action->to_addr.addr), d);
    tcph->check = bpf_csum_diff(0, 0, &tcph->check, sizeof(tcph->check), d);

    if (is_icmpx_error && icmp_err_l4_offset != 0) {
        xdp_csum_update_l4(data, data_end, icmp_err_l4_offset, icmp_err_l4_proto,
                           is_modify_source ? action->from_port : action->to_port,
                           is_modify_source ? action->to_port : action->from_port, old_addr,
                           action->to_addr.addr, true);
    }

    return 0;
}

static __always_inline void xdp_nat4_metric_accumulate(void *data, void *data_end,
                                                       struct nat4_timer_value_v3 *value,
                                                       bool ingress) {
    u64 bytes = (u64)(long)data_end - (u64)(long)data;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline int xdp_nat4_lookup_or_new_ct_egress(
    void *data, void *data_end, u32 mark, u32 ifindex, u8 l4proto, bool allow_create,
    struct inet4_pair *server_pair, struct inet4_addr *client_addr, __be16 client_port,
    struct nat4_mapping_value_v3 *ingress_val, struct nat4_timer_value_v3 **ct_out,
    struct nat4_port_queue_value_v3 *alloc_item, __be32 nat_addr, __be16 nat_port, bool created,
    bool is_dynamic) {
    bool track_ref = ingress_val && ingress_val->is_static == 0;
    u16 gen_snap = track_ref ? ingress_val->generation : 0;
    struct nat_timer_key_v4 tkey = {0};
    tkey.l4proto = l4proto;
    __builtin_memcpy(&tkey.pair_ip, server_pair, sizeof(tkey.pair_ip));

    struct nat4_timer_value_v3 *tv = bpf_map_lookup_elem(&nat4_mapping_timer_v3, &tkey);
    if (tv) {
        if (track_ref && gen_snap != 0 && tv->generation_snapshot != gen_snap) {
            bpf_map_delete_elem(&nat4_mapping_timer_v3, &tkey);
            tv = NULL;
        } else if (tv->status == TIMER_PENDING_REF) {
            return TIMER_ERROR;
        } else {
            *ct_out = tv;
            return TIMER_EXIST;
        }
    }
    if (!allow_create) return TIMER_NOT_FOUND;

    struct nat4_timer_value_v3 nv = {0};
    nv.client_port = client_port;
    nv.client_status = CT_INIT;
    nv.server_status = CT_INIT;
    nv.gress = NAT_MAPPING_EGRESS;
    nv.client_addr = *client_addr;
    nv.create_time = bpf_ktime_get_tai_ns();
    nv.flow_id = get_flow_id(mark);
    nv.cpu_id = bpf_get_smp_processor_id();
    nv.ifindex = ifindex;
    nv.generation_snapshot = gen_snap;
    nv.status = track_ref ? TIMER_PENDING_REF : TIMER_INIT;

    tv = nat4_v3_insert_ct(&tkey, &nv);
    if (!tv) return TIMER_ERROR;

    if (track_ref) {
        if (nat4_v3_state_try_inc(ingress_val) != 0) {
            bpf_map_delete_elem(&nat4_mapping_timer_v3, &tkey);
            return TIMER_ERROR;
        }
        tv->status = TIMER_INIT;
    }

    *ct_out = tv;
    return TIMER_CREATED;
}

static __always_inline int xdp_nat4_lookup_or_new_ct_ingress(
    void *data, void *data_end, u32 mark, u32 ifindex, u8 l4proto, bool do_new,
    struct inet4_pair *server_pair, struct inet4_addr *client_addr, __be16 client_port,
    struct nat4_mapping_value_v3 *ingress_val, struct nat4_timer_value_v3 **ct_out) {
    bool track_ref = ingress_val && ingress_val->is_static == 0;
    u16 gen_snap = track_ref ? ingress_val->generation : 0;
    struct nat_timer_key_v4 tkey = {0};
    tkey.l4proto = l4proto;
    __builtin_memcpy(&tkey.pair_ip, server_pair, sizeof(tkey.pair_ip));

    struct nat4_timer_value_v3 *tv = bpf_map_lookup_elem(&nat4_mapping_timer_v3, &tkey);
    if (tv) {
        if (track_ref && gen_snap != 0 && tv->generation_snapshot != gen_snap) {
            bpf_map_delete_elem(&nat4_mapping_timer_v3, &tkey);
            tv = NULL;
        } else if (tv->status == TIMER_PENDING_REF) {
            return TIMER_ERROR;
        } else {
            *ct_out = tv;
            return TIMER_EXIST;
        }
    }
    if (!do_new) return TIMER_NOT_FOUND;

    struct nat4_timer_value_v3 nv = {0};
    nv.client_port = client_port;
    nv.client_status = CT_INIT;
    nv.server_status = CT_INIT;
    nv.gress = NAT_MAPPING_INGRESS;
    nv.client_addr = *client_addr;
    nv.create_time = bpf_ktime_get_tai_ns();
    nv.flow_id = get_flow_id(mark);
    nv.cpu_id = bpf_get_smp_processor_id();
    nv.ifindex = ifindex;
    nv.generation_snapshot = gen_snap;
    nv.status = track_ref ? TIMER_PENDING_REF : TIMER_INIT;

    tv = nat4_v3_insert_ct(&tkey, &nv);
    if (!tv) return TIMER_ERROR;

    if (track_ref) {
        if (nat4_v3_state_try_inc(ingress_val) != 0) {
            bpf_map_delete_elem(&nat4_mapping_timer_v3, &tkey);
            return TIMER_ERROR;
        }
        tv->status = TIMER_INIT;
    }

    *ct_out = tv;
    return TIMER_CREATED;
}

static __always_inline int xdp_nat4_egress_ct_cleanup(u8 l4proto, __be32 nat_addr, __be16 nat_port,
                                                      __be32 client_addr, __be16 client_port,
                                                      bool created, bool is_dynamic,
                                                      struct nat4_mapping_value_v3 *ingress_val,
                                                      struct nat4_port_queue_value_v3 *alloc_item) {
    if (created && is_dynamic &&
        ingress_val->state_ref == nat4_v3_state_make(NAT4_V3_STATE_ACTIVE, 0)) {
        nat4_v3_delete_mapping_pair(l4proto, nat_addr, nat_port, client_addr, client_port);
        (void)nat4_v3_queue_push(l4proto, alloc_item);
    }
    return -1;
}

static __always_inline int xdp_nat4_dyn_egress_lookup(u32 wan_ifindex, u32 mark, u8 l4proto,
                                                      const struct inet4_pair *pair,
                                                      struct nat4_mapping_value_v3 **egress,
                                                      struct nat4_mapping_value_v3 **ingress,
                                                      bool *created) {
    struct nat_mapping_key_v4 egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = l4proto,
        .from_port = pair->src_port,
        .from_addr = pair->src_addr.addr,
    };

    struct nat4_mapping_value_v3 *egress_val = bpf_map_lookup_elem(&nat4_dyn_map, &egress_key);
    if (egress_val) {
        struct nat_mapping_key_v4 ingress_key = {
            .gress = NAT_MAPPING_INGRESS,
            .l4proto = l4proto,
            .from_addr = egress_val->addr,
            .from_port = egress_val->port,
        };
        struct nat4_mapping_value_v3 *ingress_val =
            bpf_map_lookup_elem(&nat4_dyn_map, &ingress_key);
        if (!ingress_val || ingress_val->addr != pair->src_addr.addr ||
            ingress_val->port != pair->src_port) {
            bpf_map_delete_elem(&nat4_dyn_map, &egress_key);
        } else {
            *egress = egress_val;
            *ingress = ingress_val;
            return 0;
        }
    }

    egress_val = NULL;
    struct nat4_mapping_value_v3 *ingress_val = NULL;
    if (xdp_nat4_static_egress_lookup(l4proto, pair, &egress_val, &ingress_val) == 0) {
        *egress = egress_val;
        *ingress = ingress_val;
        return 0;
    }

    struct wan_ip_info_key wan_key = {
        .ifindex = wan_ifindex,
        .l3_protocol = LANDSCAPE_IPV4_TYPE,
    };
    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_info) return -1;

    struct nat4_port_queue_value_v3 alloc_item = {};
    if (nat4_v3_alloc_port(l4proto, &alloc_item)) return -1;

    u16 generation = alloc_item.last_generation + 1;
    struct nat4_mapping_value_v3 new_value = {
        .state_ref = 0,
        .addr = wan_info->addr.ip,
        .trigger_addr = pair->dst_addr.addr,
        .port = alloc_item.port,
        .trigger_port = pair->dst_port,
        .generation = 0,
        .is_static = 0,
        .is_allow_reuse = get_flow_allow_reuse_port(mark) ? 1 : 0,
    };

    struct nat4_mapping_value_v3 *ingress_out = NULL;
    struct nat4_mapping_value_v3 *egress_out =
        nat4_v3_insert_mappings_v4(&egress_key, &new_value, generation, &ingress_out);
    if (!egress_out || !ingress_out) {
        (void)nat4_v3_queue_push(l4proto, &alloc_item);
        return -1;
    }

    *egress = egress_out;
    *ingress = ingress_out;
    *created = true;
    return 0;
}

#endif /* __LD_XDP_NAT4_H__ */
