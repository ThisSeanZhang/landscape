#ifndef __LD_XDP_NAT4_H__
#define __LD_XDP_NAT4_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../landscape.h"
#include "nat_common.h"
#include "nat4_map_ops.h"
#include "nat4_ct_timer.h"
#include "../land_wan_ip.h"
#include "../scanner/xdp_scanner4.h"
#include "../fragment/frag_common.h"
#include "../fragment/xdp_frag4.h"
#include "xdp_csum_helpers.h"

static __always_inline int xdp_read_nat_info4(void *data, void *data_end,
                                              const struct scan_ipv4_idx *idx,
                                              struct inet4_pair *pair) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return -1;

    pair->src_addr.addr = iph->saddr;
    pair->dst_addr.addr = iph->daddr;

    if (idx->icmp_error_l3_offset > 0) {
        struct iphdr *inner_ip = data + idx->icmp_error_l3_offset;
        if ((void *)(inner_ip + 1) > data_end) return -1;
        pair->src_addr.addr = inner_ip->daddr;
    }

    if (idx->fragment_type >= FRAG_MIDDLE) return 0;

    u8 l4_protocol = idx->l4_protocol;
    u16 l4_offset = idx->l4_offset;

    if (idx->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->dst_port = tcph->source;
        pair->src_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (idx->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->dst_port = udph->source;
        pair->src_port = udph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMP || l4_protocol == IPPROTO_ICMPV6) {
        u32 offset = l4_offset;
        if (idx->icmp_error_inner_l4_offset > 0) {
            offset = idx->icmp_error_inner_l4_offset;
        }
        struct icmphdr *icmph = data + offset;
        if ((void *)(icmph + 1) > data_end) return -1;
        pair->src_port = pair->dst_port = icmph->un.echo.id;
    }

    return 0;
}

static __always_inline int xdp_csum_update_l4(void *data, void *data_end, u16 l4_offset,
                                              u8 l4_protocol, __be16 old_port, __be16 new_port,
                                              __be32 old_addr, __be32 new_addr,
                                              bool is_icmp_error) {
    __be32 old_port32 = (__be32)old_port;
    __be32 new_port32 = (__be32)new_port;
    __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
    __wsum da = bpf_csum_diff(&old_addr, 4, &new_addr, 4, 0);
    __wsum combined = xdp_csum_add(dp, da);

    if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        tcph->check = xdp_csum_apply(tcph->check, combined);
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        if (udph->check != 0 || is_icmp_error) {
            udph->check = xdp_csum_apply(udph->check, combined);
        }
    }

    return 0;
}

static __always_inline int xdp_modify_headers_v4(void *data, void *data_end, u16 l4_offset,
                                                 u8 l4_protocol, bool is_modify_source,
                                                 const struct nat4_action *action,
                                                 bool is_icmp_error, u16 icmp_err_l3_offset,
                                                 u16 icmp_err_l4_offset, u8 icmp_err_l4_proto) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return -1;

    __be32 old_addr = is_modify_source ? iph->saddr : iph->daddr;
    if (is_modify_source)
        iph->saddr = action->to_addr.addr;
    else
        iph->daddr = action->to_addr.addr;
    {
        __wsum da = bpf_csum_diff(&old_addr, 4, &action->to_addr.addr, 4, 0);
        iph->check = xdp_csum_apply(iph->check, da);
    }

    if (l4_protocol == IPPROTO_ICMP) {
        if (is_icmp_error) {
            struct iphdr *inner_ip = data + icmp_err_l3_offset;
            if ((void *)(inner_ip + 1) > data_end) return -1;

            __be32 inner_old_addr = is_modify_source ? inner_ip->daddr : inner_ip->saddr;
            if (is_modify_source)
                inner_ip->daddr = action->to_addr.addr;
            else
                inner_ip->saddr = action->to_addr.addr;

            __wsum inner_addr_delta =
                bpf_csum_diff(&inner_old_addr, 4, &action->to_addr.addr, 4, 0);

            __be16 prev_inner_ip_csum = inner_ip->check;
            inner_ip->check = xdp_csum_apply(inner_ip->check, inner_addr_delta);

            struct icmphdr *icmph = data + l4_offset;
            if ((void *)(icmph + 1) > data_end) return -1;

            /* ICMP checksum covers inner IP header: reflect both addr change
             * and inner IP csum field change */
            icmph->checksum = xdp_csum_apply(icmph->checksum, inner_addr_delta);
            {
                /* Inner IP csum changed from prev_inner_ip_csum to inner_ip->check.
                 * Both are 2 bytes — pad to __be32. */
                __be32 old_ics32 = (__be32)prev_inner_ip_csum;
                __be32 new_ics32 = (__be32)inner_ip->check;
                __wsum inner_csum_delta = bpf_csum_diff(&old_ics32, 4, &new_ics32, 4, 0);
                icmph->checksum = xdp_csum_apply(icmph->checksum, inner_csum_delta);
            }

            if (icmp_err_l4_offset != 0) {
                if (icmp_err_l4_proto == IPPROTO_TCP) {
                    struct tcphdr *inner_tcp = data + icmp_err_l4_offset;
                    if ((void *)(inner_tcp + 1) > data_end) return -1;

                    __be16 inner_old_port = is_modify_source ? inner_tcp->dest : inner_tcp->source;
                    if (is_modify_source)
                        inner_tcp->dest = action->to_port;
                    else
                        inner_tcp->source = action->to_port;

                    __be16 prev_inner_tcp_csum = inner_tcp->check;

                    /* Inner TCP: port change (padded to __be32) */
                    __be32 old_tport32 = (__be32)inner_old_port;
                    __be32 new_tport32 = (__be32)action->to_port;
                    __wsum tport_delta = bpf_csum_diff(&old_tport32, 4, &new_tport32, 4, 0);
                    inner_tcp->check = xdp_csum_apply(inner_tcp->check, tport_delta);

                    /* Inner TCP: pseudo-header address change */
                    __wsum taddr_delta =
                        bpf_csum_diff(&inner_old_addr, 4, &action->to_addr.addr, 4, 0);
                    inner_tcp->check = xdp_csum_apply(inner_tcp->check, taddr_delta);

                    /* ICMP reflects: inner TCP csum change + inner TCP port change */
                    {
                        __be32 old_tcs32 = (__be32)prev_inner_tcp_csum;
                        __be32 new_tcs32 = (__be32)inner_tcp->check;
                        __wsum tcp_csum_delta = bpf_csum_diff(&old_tcs32, 4, &new_tcs32, 4, 0);
                        icmph->checksum = xdp_csum_apply(icmph->checksum, tcp_csum_delta);
                    }
                    icmph->checksum = xdp_csum_apply(icmph->checksum, tport_delta);
                } else if (icmp_err_l4_proto == IPPROTO_UDP) {
                    struct udphdr *inner_udp = data + icmp_err_l4_offset;
                    if ((void *)(inner_udp + 1) > data_end) return -1;

                    __be16 inner_old_port = is_modify_source ? inner_udp->dest : inner_udp->source;
                    if (is_modify_source)
                        inner_udp->dest = action->to_port;
                    else
                        inner_udp->source = action->to_port;

                    __be16 prev_inner_udp_csum = inner_udp->check;
                    __be32 old_uport32 = (__be32)inner_old_port;
                    __be32 new_uport32 = (__be32)action->to_port;
                    __wsum uport_delta = bpf_csum_diff(&old_uport32, 4, &new_uport32, 4, 0);

                    if (inner_udp->check != 0) {
                        inner_udp->check = xdp_csum_apply(inner_udp->check, uport_delta);

                        __wsum uaddr_delta =
                            bpf_csum_diff(&inner_old_addr, 4, &action->to_addr.addr, 4, 0);
                        inner_udp->check = xdp_csum_apply(inner_udp->check, uaddr_delta);
                    }

                    /* ICMP reflects: inner UDP csum change + inner UDP port change */
                    {
                        __be32 old_ucs32 = (__be32)prev_inner_udp_csum;
                        __be32 new_ucs32 = (__be32)inner_udp->check;
                        __wsum udp_csum_delta = bpf_csum_diff(&old_ucs32, 4, &new_ucs32, 4, 0);
                        icmph->checksum = xdp_csum_apply(icmph->checksum, udp_csum_delta);
                    }
                    icmph->checksum = xdp_csum_apply(icmph->checksum, uport_delta);
                } else if (icmp_err_l4_proto == IPPROTO_ICMP) {
                    struct icmphdr *inner_icmp = data + icmp_err_l4_offset;
                    if ((void *)(inner_icmp + 1) > data_end) return -1;

                    __be16 prev_inner_icmp_csum = inner_icmp->checksum;
                    __be32 old_id32 = (__be32)inner_icmp->un.echo.id;
                    __be32 new_id32 = (__be32)action->to_port;
                    __wsum id_delta = bpf_csum_diff(&old_id32, 4, &new_id32, 4, 0);

                    inner_icmp->un.echo.id = action->to_port;
                    inner_icmp->checksum = xdp_csum_apply(inner_icmp->checksum, id_delta);

                    __be32 old_ics32 = (__be32)prev_inner_icmp_csum;
                    __be32 new_ics32 = (__be32)inner_icmp->checksum;
                    __wsum icmp_csum_delta = bpf_csum_diff(&old_ics32, 4, &new_ics32, 4, 0);
                    icmph->checksum = xdp_csum_apply(icmph->checksum, icmp_csum_delta);
                    icmph->checksum = xdp_csum_apply(icmph->checksum, id_delta);
                }
            }
        } else {
            struct icmphdr *icmph = data + l4_offset;
            if ((void *)(icmph + 1) > data_end) return -1;
            /* ICMP echo: id → port mapping. Both fields are __be16, pad to __be32. */
            __be32 old_id32 = (__be32)icmph->un.echo.id;
            icmph->un.echo.id = action->to_port;
            __be32 new_port32 = (__be32)action->to_port;
            __wsum echo_delta = bpf_csum_diff(&old_id32, 4, &new_port32, 4, 0);
            icmph->checksum = xdp_csum_apply(icmph->checksum, echo_delta);
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
            __be32 old_port32 = (__be32)old_port;
            __be32 new_port32 = (__be32)action->to_port;
            __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
            __wsum da = bpf_csum_diff(&old_addr, 4, &action->to_addr.addr, 4, 0);
            udph->check = xdp_csum_apply(udph->check, xdp_csum_add(dp, da));
        }

        if (is_icmp_error && icmp_err_l4_offset != 0) {
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

    {
        __be32 old_port32 = (__be32)old_port;
        __be32 new_port32 = (__be32)action->to_port;
        __wsum dp = bpf_csum_diff(&old_port32, 4, &new_port32, 4, 0);
        __wsum da = bpf_csum_diff(&old_addr, 4, &action->to_addr.addr, 4, 0);
        tcph->check = xdp_csum_apply(tcph->check, xdp_csum_add(dp, da));
    }

    if (is_icmp_error && icmp_err_l4_offset != 0) {
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

static __always_inline enum ct_ingress_resolve
xdp_nat4_ct_ingress_resolve(const struct nat4_timer_key *ct_key,
                            struct nat4_timer_value_v3 **ct_out) {
    return nat4_ct_ingress_resolve(ct_key, ct_out);
}

static __always_inline int xdp_nat4_ct_resolve(const struct nat4_timer_key *ct_key,
                                               struct nat4_mapping_value_v3 *dyn_ingress,
                                               struct nat4_timer_value_v3 **ct_out) {
    return nat4_ct_resolve(ct_key, dyn_ingress, ct_out);
}

static __always_inline int
xdp_nat4_ct_create(u32 mark, u32 ifindex, const struct nat4_timer_key *ct_key,
                   const struct inet4_addr *client_addr, __be16 client_port, u8 gress,
                   struct nat4_mapping_value_v3 *dyn_ingress, struct nat4_timer_value_v3 **ct_out) {
    bool track_ref = dyn_ingress != NULL;
    u16 gen_snap = track_ref ? dyn_ingress->generation : 0;

    struct nat4_timer_value_v3 nv = {0};
    nv.client_port = client_port;
    nv.client_status = CT_INIT;
    nv.server_status = CT_INIT;
    nv.gress = gress;
    nv.client_addr = *client_addr;
    nv.create_time = bpf_ktime_get_tai_ns();
    nv.flow_id = get_flow_id(mark);
    nv.cpu_id = bpf_get_smp_processor_id();
    nv.ifindex = ifindex;
    nv.generation_snapshot = gen_snap;
    nv.is_static = dyn_ingress == NULL ? 1 : 0;
    nv.status = track_ref ? TIMER_PENDING_REF : TIMER_INIT;

    struct nat4_timer_value_v3 *tv = nat4_insert_ct(ct_key, &nv);
    if (!tv) return -1;

    if (track_ref) {
        if (nat4_state_try_inc(dyn_ingress) != 0) {
            bpf_map_delete_elem(&nat4_timer_map, ct_key);
            return -1;
        }
        tv->status = TIMER_INIT;
    }

    *ct_out = tv;
    return 0;
}

static __always_inline int xdp_nat4_st_egress_lookup(u32 wan_ifindex, u8 ip_protocol,
                                                     const struct inet4_pair *pkt_ip_pair,
                                                     struct nat4_egress_result *result) {
    struct nat4_mapping_key egress_key = {
        .gress = NAT_MAPPING_EGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->src_port,
        .from_addr = pkt_ip_pair->src_addr.addr,
    };
    struct nat4_static_value *st_egress = bpf_map_lookup_elem(&nat4_static_map, &egress_key);
    if (!st_egress && pkt_ip_pair->src_addr.addr != 0) {
        egress_key.from_addr = 0;
        st_egress = bpf_map_lookup_elem(&nat4_static_map, &egress_key);
    }
    if (!st_egress) return -1;

    if (!nat4_lookup_static_ingress(ip_protocol, st_egress->port)) return -1;

    struct wan_ip_info_key wan_key = {
        .ifindex = wan_ifindex,
        .l3_protocol = LANDSCAPE_IPV4_TYPE,
    };
    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_info) return -1;

    result->nat_addr = wan_info->addr.ip;
    result->nat_port = st_egress->port;
    return 0;
}

static __always_inline int xdp_nat4_dyn_egress_lookup_and_check(
    u32 wan_ifindex, u32 mark, u8 ip_protocol, bool allow_create,
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
                if (!is_ancestor) return -1;
            }
            if (is_ancestor) {
                u8 allow = get_flow_allow_reuse_port(mark) ? 1 : 0;
                egress_value->is_allow_reuse = allow;
                ingress_value->is_allow_reuse = allow;
            }
            return 0;
        }
    }

    if (!allow_create) return -1;

    struct wan_ip_info_key wan_key = {
        .ifindex = wan_ifindex,
        .l3_protocol = LANDSCAPE_IPV4_TYPE,
    };
    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_info) return -1;

    if (nat4_alloc_port(ip_protocol, alloc_item) != 0) return -1;

    u16 generation = alloc_item->last_generation + 1;
    struct nat4_egress_mapping_value_v3 new_value = {
        .addr = wan_info->addr.ip,
        .trigger_addr = pkt_ip_pair->dst_addr.addr,
        .port = alloc_item->port,
        .trigger_port = pkt_ip_pair->dst_port,
        .is_allow_reuse = get_flow_allow_reuse_port(mark) ? 1 : 0,
    };

    struct nat4_mapping_value_v3 *ingress_value = NULL;
    struct nat4_egress_mapping_value_v3 *egress_out =
        nat4_insert_mappings(&egress_key, &new_value, generation, &ingress_value);
    if (!egress_out || !ingress_value) {
        (void)nat4_queue_push(ip_protocol, alloc_item);
        return -1;
    }

    result->is_created = 1;
    result->nat_addr = wan_info->addr.ip;
    result->nat_port = alloc_item->port;
    *dyn_ingress_out = ingress_value;
    return 0;
}

static __always_inline int xdp_nat4_st_ingress_lookup(u8 ip_protocol,
                                                      const struct inet4_pair *pkt_ip_pair,
                                                      struct nat4_lan_result *result) {
    struct nat4_mapping_key ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = ip_protocol,
        .from_port = pkt_ip_pair->dst_port,
        .from_addr = 0,
    };

    struct nat4_static_value *st_value = bpf_map_lookup_elem(&nat4_static_map, &ingress_key);
    if (!st_value) return -1;

    result->lan_addr = st_value->addr;
    result->lan_port = st_value->port;
    return 0;
}

static __always_inline int
xdp_nat4_dyn_ingress_lookup_and_check(u8 ip_protocol, const struct inet4_pair *pkt_ip_pair,
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
    if (!dynamic_value) return -1;

    if (dynamic_value->is_allow_reuse == 0 && ip_protocol != IPPROTO_ICMP) {
        if (pkt_ip_pair->src_addr.addr != dynamic_value->trigger_addr ||
            pkt_ip_pair->src_port != dynamic_value->trigger_port)
            return -1;
    }

    result->lan_addr = dynamic_value->addr;
    result->lan_port = dynamic_value->port;
    *dyn_ingress_out = dynamic_value;
    return 0;
}

#endif /* __LD_XDP_NAT4_H__ */
