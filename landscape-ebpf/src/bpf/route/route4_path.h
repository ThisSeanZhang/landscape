#ifndef __LD_ROUTE4_PATH_H__
#define __LD_ROUTE4_PATH_H__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "base/landscape.h"

#include "route/flow4_maps.h"
#include "route/route4_cache.h"
#include "route/route4_context.h"
#include "route/route4_lan.h"
#include "route/route4_slot.h"
#include "route/route_common.h"

#include "chain/redirect_able.h"
#include "chain/tc_cb.h"
#include "route/flow_match.h"
#include "neigh/neigh_ip4.h"

static __always_inline int tc_route4_lan_redirect_check_in_wan(struct __sk_buff *skb,
                                                               u32 current_l3_offset,
                                                               struct route4_context *context) {
    int ret;
    struct route4_lan_key lan_search_key = {0};
    struct mac_key_v4 mac_key_search = {0};
    struct mac_value_v4 *mac_value = NULL;

    lan_search_key.prefixlen = 32;
    lan_search_key.addr = context->daddr;

    struct route4_lan_info *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_search_key);

    if (likely(lan_info != NULL)) {
        if (lan_info->route_type == ROUTE_TYPE_WAN) {
            if (lan_info->addr == context->daddr) return TC_ACT_UNSPEC;
            // NOTE (suspected bug): WAN-typed entry hit with addr != daddr
            // falls through into the LAN redirect tail below, i.e. F1 will
            // redirect to lan_info->ifindex. F2 (in_lan) and F3
            // (in_wan_egress) both return TC_ACT_OK here instead. Locked as
            // current behaviour by tests test_route4/6_lan_redirect_check_in_wan
            // (WAN-other row). Current WanReachable producers only publish host
            // routes (/32, addr == daddr), so this branch stays dormant;
            // revisit before any dedup refactor.
        }
        // is LAN Packet, redirect to lan
        if (unlikely(lan_info->ifindex == skb->ifindex)) {
            // current iface
            return TC_ACT_UNSPEC;
        }

        if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) {
            return TC_ACT_UNSPEC;
        }

        if (current_l3_offset == 0 && lan_info->has_mac) {
            unsigned char ethhdr[14];
            ethhdr[12] = 0x08;
            ethhdr[13] = 0x00;

            if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;

            if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
        }

        bool target_has_mac = lan_info->has_mac;
        if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
            mac_key_search.addr = lan_info->addr;
        } else {
            mac_key_search.addr = context->daddr;
        }

        if (target_has_mac) {
            mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
            if (mac_value) {
                ret = store_mac_v4(skb, mac_value->mac, lan_info->mac_addr);
                if (!ret) {
                    return bpf_redirect(lan_info->ifindex, 0);
                }
                ld_from_wan_log("store_mac_v4 err: %d", ret);
            } else {
                ld_from_wan_log("can't find mac, IP: %pI4", &mac_key_search.addr);
            }
        } else {
            return bpf_redirect(lan_info->ifindex, 0);
        }

        struct bpf_redir_neigh param;
        param.nh_family = AF_INET;

        if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
            param.ipv6_nh[0] = lan_info->addr;
        } else {
            param.ipv6_nh[0] = lan_search_key.addr;
        }

        ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
        // ld_from_wan_log("lan_info->ifindex:  %d", lan_info->ifindex);
        // ld_from_wan_log("is_ipv4:  %d", is_ipv4);
        // ld_from_wan_log("bpf_redirect_neigh ip:  %pI6", lan_search_key.addr.in6_u.u6_addr8);
        if (unlikely(ret != 7)) {
            ld_from_wan_log("bpf_redirect_neigh error: %d", ret);
        }
        // ld_from_wan_log("bpf_redirect_neigh result: %d", ret);

        return ret;
    }

    // ld_from_wan_log("lan_info pad: %d", lan_search_key._pad[0]);
    // ld_from_wan_log("lan_info pad: %d", lan_search_key._pad[1]);
    // ld_from_wan_log("lan_info pad: %d", lan_search_key._pad[2]);
    // ld_from_wan_log("lan_info prefixlen: %d", lan_search_key.prefixlen);
    // ld_from_wan_log("lan_info l3_protocol: %d", lan_search_key.l3_protocol);
    // ld_from_wan_log("lan_info ip: %pI4", lan_search_key.addr.in6_u.u6_addr8);

    return TC_ACT_OK;
}

static __always_inline int tc_route4_lan_redirect_check_in_lan(struct __sk_buff *skb,
                                                               u32 current_l3_offset,
                                                               struct route4_context *context) {
    int ret;
    struct route4_lan_key lan_search_key = {0};
    struct mac_key_v4 mac_key_search = {0};
    struct mac_value_v4 *mac_value = NULL;

    lan_search_key.prefixlen = 32;
    lan_search_key.addr = context->daddr;

    struct route4_lan_info *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_search_key);

    if (lan_info == NULL) {
        return TC_ACT_OK;
    }

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        if (lan_info->addr == context->daddr) return TC_ACT_UNSPEC;
        return TC_ACT_OK;
    }

    if (unlikely(lan_info->ifindex == skb->ingress_ifindex)) {
        if (lan_info->has_mac && lan_info->addr != 0 && lan_info->addr != context->daddr) {
            mac_key_search.addr = context->daddr;
            mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
            if (mac_value) {
                if (!bpf_skb_store_bytes(skb, 0, &mac_value->mac, 14, 0)) {
                    return bpf_redirect(lan_info->ifindex, 0);
                }
            }
        }
        return TC_ACT_UNSPEC;
    }

    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) {
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && lan_info->has_mac) {
        unsigned char ethhdr[14];
        ethhdr[12] = 0x08;
        ethhdr[13] = 0x00;

        if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;
        if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
    }

    bool target_has_mac = lan_info->has_mac;
    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        mac_key_search.addr = lan_info->addr;
    } else {
        mac_key_search.addr = context->daddr;
    }

    if (target_has_mac) {
        mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
        if (mac_value) {
            ret = store_mac_v4(skb, mac_value->mac, lan_info->mac_addr);
            if (!ret) return bpf_redirect(lan_info->ifindex, 0);
            ld_from_lan_log("store_mac_v4 err: %d", ret);
        } else {
            ld_from_lan_log("can't find mac, IP: %pI4, target ifindex: %d", &mac_key_search.addr,
                            lan_info->ifindex);
        }
    } else {
        return bpf_redirect(lan_info->ifindex, 0);
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET;

    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        param.ipv6_nh[0] = lan_info->addr;
    } else {
        param.ipv6_nh[0] = lan_search_key.addr;
    }

    ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
    if (unlikely(ret != 7)) {
        ld_from_lan_log("bpf_redirect_neigh error: %d", ret);
    }

    return ret;
}

// ── tc_route4/6_lan_redirect_check_in_wan_egress: adapted from
// tc_route4/6_lan_redirect_check_in_wan ──

static __always_inline int
tc_route4_lan_redirect_check_in_wan_egress(struct __sk_buff *skb, u32 current_l3_offset,
                                           struct route4_context *context) {
    int ret;
    struct route4_lan_key lan_search_key = {0};
    struct mac_key_v4 mac_key_search = {0};
    struct mac_value_v4 *mac_value = NULL;

    lan_search_key.prefixlen = 32;
    lan_search_key.addr = context->daddr;

    struct route4_lan_info *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_search_key);

    if (lan_info == NULL) return TC_ACT_OK;

    if (lan_info->route_type == ROUTE_TYPE_WAN) return TC_ACT_OK;

    if (unlikely(lan_info->ifindex == skb->ifindex)) return TC_ACT_UNSPEC;

    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr)
        return TC_ACT_UNSPEC;

    if (current_l3_offset == 0 && lan_info->has_mac) {
        unsigned char ethhdr[14];
        ethhdr[12] = 0x08;
        ethhdr[13] = 0x00;

        if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;
        if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
    }

    bool target_has_mac = lan_info->has_mac;
    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        mac_key_search.addr = lan_info->addr;
    } else {
        mac_key_search.addr = context->daddr;
    }

    if (target_has_mac) {
        mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
        if (mac_value) {
            ret = store_mac_v4(skb, mac_value->mac, lan_info->mac_addr);
            if (!ret) return bpf_redirect(lan_info->ifindex, 0);
            ld_from_wan_log("store_mac_v4 err: %d", ret);
        } else {
            ld_from_wan_log("can't find mac, IP: %pI4, target ifindex: %d", &mac_key_search.addr,
                            lan_info->ifindex);
        }
    } else {
        return bpf_redirect(lan_info->ifindex, 0);
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET;

    if (unlikely(lan_info->route_type == ROUTE_TYPE_NEXTHOP)) {
        param.ipv6_nh[0] = lan_info->addr;
    } else {
        param.ipv6_nh[0] = lan_search_key.addr;
    }

    ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
    if (unlikely(ret != 7)) {
        ld_from_wan_log("bpf_redirect_neigh error: %d", ret);
    }

    return ret;
}

static __always_inline int route4_flow_verdict(struct __sk_buff *skb, u32 current_l3_offset,
                                               struct route4_context *context, u32 *init_flow_id_) {
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (match_flow_id_v4(skb, current_l3_offset, context->saddr, (u32 *)&flow_id)) {
        return TC_ACT_SHOT;
    }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key_v4 ip_trie_key = {0};
    ip_trie_key.prefixlen = 32;
    ip_trie_key.addr = context->daddr;

    struct flow_ip_trie_value_v4 *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow4_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark_value = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        if (ip_flow_mark_value != NULL) {
            flow_mark_action = ip_flow_mark_value->mark;
            priority = ip_flow_mark_value->priority;
            //     ld_log("find ip map mark: %d", flow_mark_action);
            //     ld_log("get_flow_allow_reuse_port: %d",
            //                  get_flow_allow_reuse_port(flow_mark_action));
            // } else {
            //     ld_log("map id: %d", ip_rules_map);
            //     ld_log("flow_id: %d,inner ip map is empty", flow_id);
            //     ld_log("222 ip: %pI4", ip_trie_key.addr);
            //     ld_log("prefixlen: %d", ip_trie_key.prefixlen);
        }
        // } else {
        // ld_log("flow_id: %d, ip map is empty", flow_id);
    }

    struct flow_dns_match_key_v4 key = {0};
    struct flow_dns_match_value_v4 *dns_rule_value = NULL;
    key.addr = context->daddr;

    // 查询 DNS 配置信息，查看是否有转发流的配置
    void *dns_rules_map = bpf_map_lookup_elem(&flow4_dns_map, &flow_id);

    if (dns_rules_map != NULL) {
        dns_rule_value = bpf_map_lookup_elem(dns_rules_map, &key);
        if (dns_rule_value != NULL) {
            if (dns_rule_value->priority <= priority) {
                flow_mark_action = dns_rule_value->mark;
                priority = dns_rule_value->priority;
            }
            // ld_log("dns_flow_mark is:%d for: %pI4", flow_mark_action,
            // &cache_key.dst_addr.in6_u.u6_addr32[0]);
            // } else {
            // ld_log("dns_flow_mark is none for: %pI4",
            // &cache_key.dst_addr.in6_u.u6_addr32[0]);
        }
    } else {
        // ld_log("flow_id: %d, dns map is empty", *flow_id_ptr);
    }

    // ld_log("flow_id %d, flow_mark_action: %u", flow_id, flow_mark_action);
    flow_action = get_flow_action(flow_mark_action);
    // dns_flow_id = get_flow_id(flow_mark_action);
    // ld_log("flow_id %d, flow_action: %d ", flow_id, flow_action);
    if (flow_action == FLOW_KEEP_GOING) {
        // 无动作
        // ld_log("FLOW_KEEP_GOING ip: %pI4", context->daddr.in6_u.u6_addr32);
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        // ld_log("FLOW_DIRECT ip: %pI4", context->daddr.in6_u.u6_addr32);
        // RESET Flow ID
        // flow_id = 0;
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        // ld_log("FLOW_DROP ip: %pI4", context->daddr.in6_u.u6_addr32);
        return TC_ACT_SHOT;
    } else if (flow_action == FLOW_REDIRECT) {
        // ld_log("FLOW_REDIRECT ip: %pI4, flow_id: %d", context->daddr.in6_u.u6_addr32,
        //              dns_flow_id);
        // flow_id = dns_flow_id;
    }

keep_going:
    // if (flow_mark_action != 0) {
    //     ld_log("flow_mark_action value is : %u", flow_mark_action);
    //     ld_log("get_flow_id value is : %u", get_flow_id(flow_mark_action));
    //     ld_log("dst ip: %pI4", context->daddr.in6_u.u6_addr32);
    // }
    *init_flow_id_ = flow_mark_action;
    return TC_ACT_OK;
}

static __always_inline struct route4_target_info *
route4_pick_wan_target_tc(struct __sk_buff *skb, u32 current_l3_offset,
                          struct route4_context *context, u32 flow_mark) {
    const u32 resolved_flow_id = get_flow_id(flow_mark);

    if (likely(!route_flow_is_five_tuple(resolved_flow_id))) {
        struct route4_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route4_target_slot(context->daddr),
        };
        return bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
    }

    route4_ensure_l4_ports_tc(skb, current_l3_offset, context);
    if (context->has_ports) {
        struct route4_conn_key conn_key = {
            .saddr = context->saddr,
            .daddr = context->daddr,
            .sport = context->sport,
            .dport = context->dport,
            .l4_proto = context->l4_protocol,
        };
        u32 conn_slot = CONN_PIN_CACHE;
        void *conn_inner = bpf_map_lookup_elem(&rt4_conn_map, &conn_slot);
        if (conn_inner != NULL) {
            struct route_conn_value *conn_val = bpf_map_lookup_elem(conn_inner, &conn_key);
            if (conn_val != NULL && conn_val->ifindex != 0) {
                struct route_flow_target_key ft_key = {
                    .flow_id = resolved_flow_id,
                    .ifindex = conn_val->ifindex,
                };
                struct route4_target_info *pinned = bpf_map_lookup_elem(&rt4_flow_targets, &ft_key);
                if (pinned != NULL && pinned->ifindex != 0) {
                    u8 xdp_able = xdp_redirect_target_able(pinned->ifindex) ? 1 : 0;
                    u8 conn_flags =
                        (get_flow_action(flow_mark) == FLOW_DIRECT) ? ROUTE_CONN_FLAG_DIRECT : 0;
                    if (conn_val->mark_value != flow_mark || conn_val->has_mac != pinned->has_mac ||
                        conn_val->is_docker != pinned->is_docker ||
                        conn_val->xdp_redirect_able != xdp_able || conn_val->flags != conn_flags ||
                        conn_val->link_chain_id != pinned->link_chain_id) {
                        struct route_conn_value refreshed = {
                            .mark_value = flow_mark,
                            .has_mac = pinned->has_mac,
                            .is_docker = pinned->is_docker,
                            .xdp_redirect_able = xdp_able,
                            .flags = conn_flags,
                            .ifindex = pinned->ifindex,
                            .link_chain_id = pinned->link_chain_id,
                            ._pad = 0,
                        };
                        bpf_map_update_elem(conn_inner, &conn_key, &refreshed, BPF_ANY);
                    }
                    return pinned;
                }
            }
        }

        struct route4_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route4_five_tuple_slot(context->saddr, context->daddr, context->sport,
                                           context->dport, context->l4_protocol),
        };
        struct route4_target_info *target_info = bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
        if (target_info != NULL && target_info->ifindex != 0 && conn_inner != NULL) {
            u8 conn_flags =
                (get_flow_action(flow_mark) == FLOW_DIRECT) ? ROUTE_CONN_FLAG_DIRECT : 0;
            struct route_conn_value new_conn = {
                .mark_value = flow_mark,
                .has_mac = target_info->has_mac,
                .is_docker = target_info->is_docker,
                .xdp_redirect_able = xdp_redirect_target_able(target_info->ifindex) ? 1 : 0,
                .flags = conn_flags,
                .ifindex = target_info->ifindex,
                .link_chain_id = target_info->link_chain_id,
                ._pad = 0,
            };
            bpf_map_update_elem(conn_inner, &conn_key, &new_conn, BPF_ANY);
        }
        return target_info;
    }

    struct route4_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route4_target_slot(context->daddr),
    };
    return bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
}

static __always_inline int route4_redirect_by_cached_target(struct __sk_buff *skb,
                                                            u32 current_l3_offset,
                                                            struct route4_cache_value *target) {
    if (target->ifindex == skb->ifindex) {
        return TC_ACT_UNSPEC;
    }

    // stamp cb like pick_wan: tc_wan_egress_route enters the target link's
    // chain through these flags; without them the skb carries stale cb from
    // recycled sk_buffs and dies at the WAN egress root tail call.
    tc_cb_mark_forwarded(skb, target->link_chain_id);

    if (current_l3_offset == 0 && target->has_mac) {
        if (prepend_dummy_mac(skb, target->is_docker) != 0) {
            return TC_ACT_SHOT;
        }
    }

    if (target->is_docker) {
        int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, route_flow_mark_vlan_id(target->mark_value));
        if (ret) {
            return ret;
        }
        ret = bpf_redirect(target->ifindex, 0);
        return ret;
    }

    // The target WAN link's from-LAN root owns the Ethernet rewrite and
    // neighbour fallback; this cache fast path only selects the link.
    return bpf_redirect(target->ifindex, 0);
}

static __always_inline int route4_redirect_by_conn_value(struct __sk_buff *skb,
                                                         u32 current_l3_offset,
                                                         const struct route_conn_value *target) {
    if (target->ifindex == skb->ifindex) {
        return TC_ACT_UNSPEC;
    }

    tc_cb_mark_forwarded(skb, target->link_chain_id);

    if (current_l3_offset == 0 && target->has_mac) {
        if (prepend_dummy_mac(skb, target->is_docker) != 0) {
            return TC_ACT_SHOT;
        }
    }

    if (target->is_docker) {
        int ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, route_flow_mark_vlan_id(target->mark_value));
        if (ret) {
            return ret;
        }
        return bpf_redirect(target->ifindex, 0);
    }

    return bpf_redirect(target->ifindex, 0);
}

static __always_inline int route4_search_cache_in_lan(struct __sk_buff *skb,
                                                      const u32 current_l3_offset,
                                                      struct route4_context *context,
                                                      u32 *flow_mark) {
    {
        u32 key = WAN_CACHE;
        struct route4_cache_key search_key = {0};
        search_key.local_addr = context->saddr;
        search_key.remote_addr = context->daddr;

        // First WAN
        void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
        if (wan_cache) {
            struct route4_cache_value *target = bpf_map_lookup_elem(wan_cache, &search_key);
            if (target) {
                if (target->ifindex == 0) {
                    return TC_ACT_SHOT;
                }
                if (current_l3_offset == 0 && target->has_mac &&
                    prepend_dummy_mac(skb, target->is_docker))
                    return TC_ACT_SHOT;
                tc_cb_mark_forwarded(skb, target->link_chain_id);
                return bpf_redirect(target->ifindex, 0);
            }
        }

        key = LAN_CACHE;
        void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
        if (lan_cache) {
            struct route4_cache_value *target = bpf_map_lookup_elem(lan_cache, &search_key);
            if (target && target->ifindex != 0) {
                *flow_mark = target->mark_value;
                return route4_redirect_by_cached_target(skb, current_l3_offset, target);
            }
        }
    }

    if (unlikely(route_any_flow_is_five_tuple())) {
        route4_ensure_l4_ports_tc(skb, current_l3_offset, context);
        if (context->has_ports) {
            struct route4_conn_key conn_key = {
                .saddr = context->saddr,
                .daddr = context->daddr,
                .sport = context->sport,
                .dport = context->dport,
                .l4_proto = context->l4_protocol,
            };
            u32 conn_slot = CONN_PIN_CACHE;
            void *conn_inner = bpf_map_lookup_elem(&rt4_conn_map, &conn_slot);
            if (conn_inner != NULL) {
                struct route_conn_value *conn_val = bpf_map_lookup_elem(conn_inner, &conn_key);
                if (conn_val != NULL && conn_val->ifindex != 0) {
                    struct route_flow_target_key ft_key = {
                        .flow_id = get_flow_id(conn_val->mark_value),
                        .ifindex = conn_val->ifindex,
                    };
                    struct route4_target_info *live =
                        bpf_map_lookup_elem(&rt4_flow_targets, &ft_key);
                    if (live != NULL && live->ifindex != 0 &&
                        live->link_chain_id == conn_val->link_chain_id &&
                        live->has_mac == conn_val->has_mac &&
                        live->is_docker == conn_val->is_docker) {
                        *flow_mark = conn_val->mark_value;
                        return route4_redirect_by_conn_value(skb, current_l3_offset, conn_val);
                    }
                }
            }
        }
    }

    return TC_ACT_OK;
}

static __always_inline int route4_set_cache_in_wan(const struct route4_context *context,
                                                   u32 current_l3_offset, u32 ifindex,
                                                   u32 link_chain_id) {
    struct route4_cache_key search_key = {0};
    struct route4_cache_value *target = NULL;

    u32 key = LAN_CACHE;
    search_key.local_addr = context->daddr;
    search_key.remote_addr = context->saddr;

    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache != NULL) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            //     ld_from_wan_log("Already cached %pI4 -> %pI4",
            //     search_key.local_addr.in6_u.u6_addr8,
            //                 search_key.remote_addr.in6_u.u6_addr8);
            // } else {
            //     ld_from_wan_log("Already cached %pI6 -> %pI6",
            //     search_key.local_addr.in6_u.u6_addr8,
            //                 search_key.remote_addr.in6_u.u6_addr8);
            // }
            return TC_ACT_OK;
        }
    }

    key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (wan_cache) {
        target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            target->ifindex = ifindex;
            target->has_mac = current_l3_offset > 0;
            target->xdp_redirect_able = xdp_redirect_target_able(ifindex) ? 1 : 0;
            target->link_chain_id = link_chain_id;
        } else {
            struct route4_cache_value new_target_cache = {0};
            new_target_cache.has_mac = current_l3_offset > 0;
            new_target_cache.ifindex = ifindex;
            new_target_cache.xdp_redirect_able = xdp_redirect_target_able(ifindex) ? 1 : 0;
            new_target_cache.link_chain_id = link_chain_id;
            bpf_map_update_elem(wan_cache, &search_key, &new_target_cache, BPF_ANY);
            // ld_from_wan_log("wan_cache new new_target_cache.ifindex: %d",
            // new_target_cache.ifindex);
        }

        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     ld_from_wan_log("cache %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // } else {
        //     ld_from_wan_log("cache %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // }
    } else {
        ld_from_wan_log("could not find wan_cache: %d", key);
    }

    return TC_ACT_OK;
}

static __always_inline int route4_set_cache_in_lan(const struct route4_context *context,
                                                   u32 flow_mark) {
    struct route4_cache_key search_key = {0};
    struct route4_cache_value *target = NULL;
    u32 key = WAN_CACHE;

    search_key.local_addr = context->saddr;
    search_key.remote_addr = context->daddr;

    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (wan_cache) {
        target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            return TC_ACT_OK;
        }
    }

    const u32 resolved_flow_id = get_flow_id(flow_mark);
    if (unlikely(route_flow_is_five_tuple(resolved_flow_id))) {
        // FiveTuple flows never populate 2-tuple LAN_CACHE; per-connection
        // 16B entries are maintained in rt4_conn_map[CONN_PIN_CACHE].
        return TC_ACT_OK;
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache) {
        struct route4_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route4_target_slot(context->daddr),
        };
        struct route4_target_info *slot_target = bpf_map_lookup_elem(&rt4_slot_map, &slot_key);

        // The slot can disappear after pick_wan. Do not cache an unresolved target.
        if (slot_target == NULL || slot_target->ifindex == 0) return TC_ACT_OK;

        struct route4_cache_value new_target_cache = {0};
        new_target_cache.mark_value = flow_mark;
        new_target_cache.ifindex = slot_target->ifindex;
        new_target_cache.has_mac = slot_target->has_mac;
        new_target_cache.is_docker = slot_target->is_docker;
        new_target_cache.link_chain_id = slot_target->link_chain_id;
        new_target_cache.xdp_redirect_able =
            xdp_redirect_target_able(new_target_cache.ifindex) ? 1 : 0;
        bpf_map_update_elem(lan_cache, &search_key, &new_target_cache, BPF_ANY);
    }

    return TC_ACT_OK;
}

#endif /* __LD_ROUTE4_PATH_H__ */
