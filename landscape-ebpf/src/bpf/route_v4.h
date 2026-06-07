#ifndef __LD_FLOW_ROUTE_V4_H__
#define __LD_FLOW_ROUTE_V4_H__
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "land_wan_ip.h"

#include "route/route_index.h"
#include "route/route_maps_v4.h"

#include "flow_match.h"
#include "neigh_ip.h"

static __always_inline int lan_redirect_check_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                                 struct route_context_v4 *context, bool is_lan) {
#define BPF_LOG_TOPIC "lan_redirect_check_v4"

    int ret;
    struct lan_route_key_v4 lan_search_key = {0};
    struct mac_key_v4 mac_key_search = {0};
    struct mac_value_v4 *mac_value = NULL;

    lan_search_key.prefixlen = 32;
    lan_search_key.addr = context->daddr;

    struct lan_route_info_v4 *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_search_key);

    if (likely(lan_info != NULL)) {
        if (lan_info->route_type == ROUTE_TYPE_WAN) {
            if (lan_info->addr == context->daddr) return TC_ACT_UNSPEC;
        }
        // is LAN Packet, redirect to lan
        if (unlikely(lan_info->ifindex == skb->ifindex)) {
            if (is_lan && lan_info->has_mac && lan_info->addr != 0 &&
                lan_info->addr != context->daddr) {
                mac_key_search.addr = context->daddr;
                mac_value = bpf_map_lookup_elem(&ip_mac_v4, &mac_key_search);
                if (mac_value) {
                    if (!bpf_skb_store_bytes(skb, 0, &mac_value->mac, 14, 0)) {
                        return bpf_redirect(lan_info->ifindex, 0);
                    }
                }
            }
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
                ld_bpf_log("store_mac_v4 err: %d", ret);
            } else {
                ld_bpf_log("can't find mac, IP: %pI4", &mac_key_search.addr);
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
        // ld_bpf_log("lan_info->ifindex:  %d", lan_info->ifindex);
        // ld_bpf_log("is_ipv4:  %d", is_ipv4);
        // ld_bpf_log("bpf_redirect_neigh ip:  %pI6", lan_search_key.addr.in6_u.u6_addr8);
        if (unlikely(ret != 7)) {
            ld_bpf_log("bpf_redirect_neigh error: %d", ret);
        }
        // ld_bpf_log("bpf_redirect_neigh result: %d", ret);

        return ret;
    }

    // ld_bpf_log("lan_info pad: %d", lan_search_key._pad[0]);
    // ld_bpf_log("lan_info pad: %d", lan_search_key._pad[1]);
    // ld_bpf_log("lan_info pad: %d", lan_search_key._pad[2]);
    // ld_bpf_log("lan_info prefixlen: %d", lan_search_key.prefixlen);
    // ld_bpf_log("lan_info l3_protocol: %d", lan_search_key.l3_protocol);
    // ld_bpf_log("lan_info ip: %pI4", lan_search_key.addr.in6_u.u6_addr8);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int flow_verdict_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                           struct route_context_v4 *context, u32 *init_flow_id_) {
#define BPF_LOG_TOPIC "flow_verdict_v4"

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
            //     ld_bpf_log("find ip map mark: %d", flow_mark_action);
            //     ld_bpf_log("get_flow_allow_reuse_port: %d",
            //                  get_flow_allow_reuse_port(flow_mark_action));
            // } else {
            //     ld_bpf_log("map id: %d", ip_rules_map);
            //     ld_bpf_log("flow_id: %d,inner ip map is empty", flow_id);
            //     ld_bpf_log("222 ip: %pI4", ip_trie_key.addr);
            //     ld_bpf_log("prefixlen: %d", ip_trie_key.prefixlen);
        }
        // } else {
        // ld_bpf_log("flow_id: %d, ip map is empty", flow_id);
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
            // ld_bpf_log("dns_flow_mark is:%d for: %pI4", flow_mark_action,
            // &cache_key.dst_addr.ip);
            // } else {
            // ld_bpf_log("dns_flow_mark is none for: %pI4", &cache_key.dst_addr.ip);
        }
    } else {
        // ld_bpf_log("flow_id: %d, dns map is empty", *flow_id_ptr);
    }

    // ld_bpf_log("flow_id %d, flow_mark_action: %u", flow_id, flow_mark_action);
    flow_action = get_flow_action(flow_mark_action);
    // dns_flow_id = get_flow_id(flow_mark_action);
    // ld_bpf_log("flow_id %d, flow_action: %d ", flow_id, flow_action);
    if (flow_action == FLOW_KEEP_GOING) {
        // 无动作
        // ld_bpf_log("FLOW_KEEP_GOING ip: %pI4", context->daddr.in6_u.u6_addr32);
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        // ld_bpf_log("FLOW_DIRECT ip: %pI4", context->daddr.in6_u.u6_addr32);
        // RESET Flow ID
        // flow_id = 0;
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        // ld_bpf_log("FLOW_DROP ip: %pI4", context->daddr.in6_u.u6_addr32);
        return TC_ACT_SHOT;
    } else if (flow_action == FLOW_REDIRECT) {
        // ld_bpf_log("FLOW_REDIRECT ip: %pI4, flow_id: %d", context->daddr.in6_u.u6_addr32,
        //              dns_flow_id);
        // flow_id = dns_flow_id;
    }

keep_going:
    // if (flow_mark_action != 0) {
    //     ld_bpf_log("flow_mark_action value is : %u", flow_mark_action);
    //     ld_bpf_log("get_flow_id value is : %u", get_flow_id(flow_mark_action));
    //     ld_bpf_log("dst ip: %pI4", context->daddr.in6_u.u6_addr32);
    // }
    *init_flow_id_ = flow_mark_action;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int pick_wan_and_send_by_flow_id_v4(struct __sk_buff *skb,
                                                           u32 current_l3_offset,
                                                           const struct route_context_v4 *context,
                                                           const u32 flow_id) {
#define BPF_LOG_TOPIC "pick_wan_and_send_by_flow_id_v4"

    int ret;
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route_target_slot_key_v4 slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route_target_slot_v4(context->daddr),
    };
    struct route_target_info_v4 *target_info = bpf_map_lookup_elem(&rt4_target_slot_map, &slot_key);

    // 找不到转发的 target 按照原有计划进行处理
    if (target_info == NULL) {
        if (resolved_flow_id == 0) {
            // Default flow PASS
            return TC_ACT_UNSPEC;
        } else {
            ld_bpf_log("DROP flow_id v4: %d, ip: %pI4", resolved_flow_id, &context->saddr);
            // Other DROP
            return TC_ACT_SHOT;
        }
    }

    if (target_info->ifindex == skb->ifindex) {
        // Belongs to the current ifindex No redirection required
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && target_info->has_mac) {
        if (prepend_dummy_mac(skb) != 0) {
            ld_bpf_log("add dummy_mac fail");
            return TC_ACT_SHOT;
        }
    }

    if (target_info->is_docker) {
        ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(resolved_flow_id));
        if (ret) {
            ld_bpf_log("bpf_skb_vlan_push error");
        }
        ret = bpf_redirect(target_info->ifindex, 0);
        if (ret != 7) {
            ld_bpf_log("bpf_redirect docker error: %d", ret);
        }
        return ret;
    }

    bool target_has_mac = target_info->has_mac;

    if (!target_has_mac) {
        return bpf_redirect(target_info->ifindex, 0);
    } else {
        struct mac_value_v4 *mac_value = bpf_map_lookup_elem(&ip_mac_v4, &target_info->gate_addr);
        if (mac_value) {
            ret = store_mac_v4(skb, mac_value->mac, target_info->mac);
            if (!ret) {
                return bpf_redirect(target_info->ifindex, 0);
            }
        }
    }

    // ld_bpf_log("wan_route_info ip: %pI4 ", target_info->gate_addr.in6_u.u6_addr8);
    // ld_bpf_log("wan_route_info target_info->ifindex: %d ",target_info->ifindex);

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET;

    param.ipv6_nh[0] = target_info->gate_addr;
    ret = bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
    if (ret != 7) {
        ld_bpf_log("bpf_redirect_neigh error: %d", ret);
    }
    return ret;

#undef BPF_LOG_TOPIC
}

static __always_inline int is_current_wan_packet_v4(struct __sk_buff *skb, u32 current_l3_offset,
                                                    struct route_context_v4 *context) {
#define BPF_LOG_TOPIC "is_current_wan_packet_v4"

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = skb->ingress_ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV4_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (wan_ip_info != NULL) {
        // Check if the current DST IP is the IP that enters the WAN network card
        // ld_bpf_log("wan_ip_info ip: %pI6", &wan_ip_info->addr);
        if (wan_ip_info->addr.ip == context->daddr) {
            return TC_ACT_UNSPEC;
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int redirect_by_cached_target_v4(struct __sk_buff *skb,
                                                        u32 current_l3_offset,
                                                        struct rt_cache_value_v4 *target) {
    if (target->ifindex == skb->ifindex) {
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && target->has_mac) {
        if (prepend_dummy_mac(skb) != 0) {
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

    if (!target->has_mac) {
        return bpf_redirect(target->ifindex, 0);
    } else {
        struct mac_value_v4 *mac_value = bpf_map_lookup_elem(&ip_mac_v4, &target->gate_addr);
        if (mac_value) {
            int ret = store_mac_v4(skb, mac_value->mac, target->mac);
            if (!ret) {
                return bpf_redirect(target->ifindex, 0);
            }
        }
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET;
    param.ipv6_nh[0] = target->gate_addr;
    return bpf_redirect_neigh(target->ifindex, &param, sizeof(param), 0);
}

static __always_inline int search_route_in_lan_v4(struct __sk_buff *skb,
                                                  const u32 current_l3_offset,
                                                  const struct route_context_v4 *context,
                                                  u32 *flow_mark) {
#define BPF_LOG_TOPIC "search_route_in_lan_v4"
    int ret = 0;
    u32 key = WAN_CACHE;
    struct rt_cache_key_v4 search_key = {0};
    struct mac_value_v4 *mac_value = NULL;
    search_key.local_addr = context->saddr;
    search_key.remote_addr = context->daddr;

    // Fist WAN
    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value_v4 *target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            struct wan_ip_info_key wan_search_key = {0};
            wan_search_key.ifindex = target->ifindex;
            wan_search_key.l3_protocol = LANDSCAPE_IPV4_TYPE;

            struct wan_ip_info_value *wan_ip_info =
                bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
            if (wan_ip_info != NULL) {
                bool target_has_mac = target->has_mac;

                if (!target_has_mac) {
                    return bpf_redirect(target->ifindex, 0);
                } else {
                    mac_value = bpf_map_lookup_elem(&ip_mac_v4, &search_key.remote_addr);
                    if (mac_value) {
                        // ld_bpf_log("find ip: %pI4 mac, send to ifindex: %d",
                        //            &search_key.remote_addr, target->ifindex);
                        if (!bpf_skb_store_bytes(skb, 0, &mac_value->mac, 14, 0)) {
                            return bpf_redirect(target->ifindex, 0);
                        }
                    } else {
                        mac_value = bpf_map_lookup_elem(&ip_mac_v4, &wan_ip_info->gateway.ip);
                        if (mac_value) {
                            // ld_bpf_log("find ip: %pI4 mac, send to ifindex: %d",
                            //            &wan_ip_info->gateway.ip, target->ifindex);
                            if (!bpf_skb_store_bytes(skb, 0, &mac_value->mac, 14, 0)) {
                                return bpf_redirect(target->ifindex, 0);
                            }
                        }
                    }
                }

                struct bpf_redir_neigh param;
                param.nh_family = AF_INET;

                COPY_ADDR_FROM(param.ipv6_nh, wan_ip_info->gateway.bits);
                ret = bpf_redirect_neigh(target->ifindex, &param, sizeof(param), 0);
                return ret;
            }
        }
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache) {
        struct rt_cache_value_v4 *target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            *flow_mark = target->mark_value;
            if (target->ifindex != 0) {
                return redirect_by_cached_target_v4(skb, current_l3_offset, target);
            }
            return pick_wan_and_send_by_flow_id_v4(skb, current_l3_offset, context,
                                                   target->mark_value);
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int setting_cache_in_wan_v4(const struct route_context_v4 *context,
                                                   u32 current_l3_offset, u32 ifindex) {
#define BPF_LOG_TOPIC "setting_cache_in_wan_v4"
    struct rt_cache_key_v4 search_key = {0};
    struct rt_cache_value_v4 *target = NULL;

    u32 key = LAN_CACHE;
    search_key.local_addr = context->daddr;
    search_key.remote_addr = context->saddr;

    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache != NULL) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            //     ld_bpf_log("Already cached %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
            //                 search_key.remote_addr.in6_u.u6_addr8);
            // } else {
            //     ld_bpf_log("Already cached %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
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
        } else {
            struct rt_cache_value_v4 new_target_cache = {0};
            new_target_cache.has_mac = current_l3_offset > 0;
            new_target_cache.ifindex = ifindex;
            // if (new_target_cache.has_mac) {
            //     struct wan_ip_info_value *wan_ip = bpf_map_lookup_elem(wan_cache, &search_key);
            //     if (wan_ip) {

            //         __builtin_memcpy(match_key.mac.mac, mac, 6);
            //     }
            // }
            bpf_map_update_elem(wan_cache, &search_key, &new_target_cache, BPF_ANY);
            // ld_bpf_log("wan_cache new new_target_cache.ifindex: %d", new_target_cache.ifindex);
        }

        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     ld_bpf_log("cache %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // } else {
        //     ld_bpf_log("cache %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // }
    } else {
        ld_bpf_log("could not find wan_cache: %d", key);
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int setting_cache_in_lan_v4(const struct route_context_v4 *context,
                                                   u32 flow_mark) {
#define BPF_LOG_TOPIC "setting_cache_in_lan_v4"
    struct rt_cache_key_v4 search_key = {0};
    struct rt_cache_value_v4 *target = NULL;
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

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            target->mark_value = flow_mark;
        } else {
            const u32 resolved_flow_id = get_flow_id(flow_mark);
            struct route_target_slot_key_v4 slot_key = {
                .flow_id = resolved_flow_id,
                .slot = route_target_slot_v4(context->daddr),
            };
            struct route_target_info_v4 *slot_target =
                bpf_map_lookup_elem(&rt4_target_slot_map, &slot_key);

            struct rt_cache_value_v4 new_target_cache = {0};
            new_target_cache.mark_value = flow_mark;
            if (slot_target != NULL) {
                new_target_cache.ifindex = slot_target->ifindex;
                new_target_cache.has_mac = slot_target->has_mac;
                new_target_cache.is_docker = slot_target->is_docker;
                new_target_cache.gate_addr = slot_target->gate_addr;
                __builtin_memcpy(new_target_cache.mac, slot_target->mac, 6);
            }
            bpf_map_update_elem(lan_cache, &search_key, &new_target_cache, BPF_ANY);
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_FLOW_ROUTE_V4_H__ */
