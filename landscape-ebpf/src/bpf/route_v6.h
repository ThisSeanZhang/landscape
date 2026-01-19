#ifndef __LD_FLOW_ROUTE_v6_H__
#define __LD_FLOW_ROUTE_v6_H__

#include <bpf/bpf_helpers.h>

#include "landscape.h"
#include "land_wan_ip.h"

#include "route/route_index.h"
#include "route/route_maps_v6.h"

#include "flow_match.h"
#include "neigh_ip.h"

// TODO: split two function
static __always_inline int lan_redirect_check_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                                 struct route_context_v6 *context) {
#define BPF_LOG_TOPIC "lan_redirect_check_v6"

    int ret;
    struct lan_route_key_v6 lan_search_key = {0};

    lan_search_key.prefixlen = 128;
    COPY_ADDR_FROM(lan_search_key.addr.bytes, context->daddr.bytes);

    struct lan_route_info_v6 *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &lan_search_key);

    if (lan_info == NULL) {
        // bpf_log_info("lan_info is null, address is: %pI6", context->daddr.bytes);
        return TC_ACT_OK;
    }

    // is LAN Packet, redirect to lan
    if (unlikely(lan_info->ifindex == skb->ifindex)) {
        // current iface
        return TC_ACT_UNSPEC;
    }

    if (!lan_info->is_next_hop && ip_addr_equal(&lan_info->addr, &context->daddr)) {
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && lan_info->has_mac) {
        unsigned char ethhdr[14];
        ethhdr[12] = 0x86;
        ethhdr[13] = 0xdd;

        if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;

        if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
    }

    bool target_has_mac = lan_info->has_mac;
    struct mac_key_v6 mac_key_search = {0};
    if (unlikely(lan_info->is_next_hop)) {
        COPY_ADDR_FROM(mac_key_search.addr.all, lan_info->addr.all);
    } else {
        COPY_ADDR_FROM(mac_key_search.addr.all, context->daddr.all);
    }

    if (target_has_mac) {
        struct mac_value_v6 *mac_value = bpf_map_lookup_elem(&ip_mac_v6, &mac_key_search);
        if (mac_value) {
            ret = store_mac_v6(skb, &mac_value->mac, lan_info->mac_addr);
            if (!ret) {
                return bpf_redirect(lan_info->ifindex, 0);
            }
            bpf_log_info("store_mac_v6 err: %d", ret);
        } else {
            bpf_log_info("can't find mac, IP: %pI6", &mac_key_search.addr);
        }
    } else {
        return bpf_redirect(lan_info->ifindex, 0);
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET6;

    if (unlikely(lan_info->is_next_hop)) {
        COPY_ADDR_FROM(param.ipv6_nh, lan_info->addr.all);
    } else {
        COPY_ADDR_FROM(param.ipv6_nh, lan_search_key.addr.all);
    }

    ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
    // bpf_log_info("lan_info->ifindex:  %d", lan_info->ifindex);
    // bpf_log_info("is_ipv4:  %d", is_ipv4);
    // bpf_log_info("bpf_redirect_neigh ip:  %pI6", lan_search_key.addr.in6_u.u6_addr8);
    if (unlikely(ret != 7)) {
        bpf_log_info("bpf_redirect_neigh error: %d", ret);
    }
    // bpf_log_info("bpf_redirect_neigh result: %d", ret);

    return ret;

    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[0]);
    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[1]);
    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[2]);
    // bpf_log_info("lan_info prefixlen: %d", lan_search_key.prefixlen);
    // bpf_log_info("lan_info l3_protocol: %d", lan_search_key.l3_protocol);
    // bpf_log_info("lan_info ip: %pI4", lan_search_key.addr.in6_u.u6_addr8);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int flow_verdict_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                           struct route_context_v6 *context, u32 *init_flow_id_) {
#define BPF_LOG_TOPIC "flow_verdict_v6"

    int ret;
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (match_flow_id_v6(skb, current_l3_offset, &context->saddr, &flow_id)) {
        return TC_ACT_SHOT;
    }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key_v6 ip_trie_key = {0};
    ip_trie_key.prefixlen = 128;
    COPY_ADDR_FROM(ip_trie_key.addr.bytes, context->daddr.bytes);

    struct flow_ip_trie_value_v6 *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow6_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark_value = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        if (ip_flow_mark_value != NULL) {
            flow_mark_action = ip_flow_mark_value->mark;
            priority = ip_flow_mark_value->priority;
            //     bpf_log_info("find ip map mark: %d", flow_mark_action);
            //     bpf_log_info("get_flow_allow_reuse_port: %d",
            //                  get_flow_allow_reuse_port(flow_mark_action));
            // } else {
            //     bpf_log_info("map id: %d", ip_rules_map);
            //     bpf_log_info("flow_id: %d,inner ip map is empty", flow_id);
            //     bpf_log_info("222 ip: %pI4", ip_trie_key.addr);
            //     bpf_log_info("prefixlen: %d", ip_trie_key.prefixlen);
        }
        // } else {
        // bpf_log_info("flow_id: %d, ip map is empty", flow_id);
    }

    struct flow_dns_match_key_v6 key = {0};
    struct flow_dns_match_value_v6 *dns_rule_value = NULL;
    key.addr = context->daddr;

    // 查询 DNS 配置信息，查看是否有转发流的配置
    void *dns_rules_map = bpf_map_lookup_elem(&flow6_dns_map, &flow_id);

    if (dns_rules_map != NULL) {
        dns_rule_value = bpf_map_lookup_elem(dns_rules_map, &key);
        if (dns_rule_value != NULL) {
            if (dns_rule_value->priority <= priority) {
                flow_mark_action = dns_rule_value->mark;
                priority = dns_rule_value->priority;
            }
            // bpf_log_info("dns_flow_mark is:%d for: %pI4", flow_mark_action,
            // &cache_key.dst_addr.ip);
            // } else {
            // bpf_log_info("dns_flow_mark is none for: %pI4", &cache_key.dst_addr.ip);
        }
    } else {
        // bpf_log_info("flow_id: %d, dns map is empty", *flow_id_ptr);
    }

    // bpf_log_info("flow_id %d, flow_mark_action: %u", flow_id, flow_mark_action);
    flow_action = get_flow_action(flow_mark_action);
    // dns_flow_id = get_flow_id(flow_mark_action);
    // bpf_log_info("flow_id %d, flow_action: %d ", flow_id, flow_action);
    if (flow_action == FLOW_KEEP_GOING) {
        // 无动作
        // bpf_log_info("FLOW_KEEP_GOING ip: %pI4", context->daddr.in6_u.u6_addr32);
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        // bpf_log_info("FLOW_DIRECT ip: %pI4", context->daddr.in6_u.u6_addr32);
        // RESET Flow ID
        // flow_id = 0;
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        // bpf_log_info("FLOW_DROP ip: %pI4", context->daddr.in6_u.u6_addr32);
        return TC_ACT_SHOT;
    } else if (flow_action == FLOW_REDIRECT) {
        // bpf_log_info("FLOW_REDIRECT ip: %pI4, flow_id: %d", context->daddr.in6_u.u6_addr32,
        //              dns_flow_id);
        // flow_id = dns_flow_id;
    }

keep_going:
    // if (flow_mark_action != 0) {
    //     bpf_log_info("flow_mark_action value is : %u", flow_mark_action);
    //     bpf_log_info("get_flow_id value is : %u", get_flow_id(flow_mark_action));
    //     bpf_log_info("dst ip: %pI4", context->daddr.in6_u.u6_addr32);
    // }
    *init_flow_id_ = flow_mark_action;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int pick_wan_and_send_by_flow_id_v6(struct __sk_buff *skb,
                                                           u32 current_l3_offset,
                                                           struct route_context_v6 *context,
                                                           const u32 flow_id) {
#define BPF_LOG_TOPIC "pick_wan_and_send_by_flow_id_v6"

    int ret;
    struct route_target_key_v6 wan_key = {0};
    wan_key.flow_id = get_flow_id(flow_id);

    struct route_target_info_v6 *target_info = bpf_map_lookup_elem(&rt6_target_map, &wan_key);

    // 找不到转发的 target 按照原有计划进行处理
    if (target_info == NULL) {
        if (wan_key.flow_id == 0) {
            // Default flow PASS
            return TC_ACT_UNSPEC;
        } else {
            bpf_log_info("DROP flow_id v6: %d", wan_key.flow_id);
            // Other DROP
            return TC_ACT_SHOT;
        }
    }

    if (target_info->ifindex == skb->ifindex) {
        // Belongs to the current ifindex No redirection required
        return TC_ACT_UNSPEC;
    }

    if (current_l3_offset == 0 && target_info->has_mac) {
        if (prepend_dummy_mac_v6(skb) != 0) {
            bpf_log_error("add dummy_mac fail");
            return TC_ACT_SHOT;
        }
    }

    if (target_info->is_docker) {
        ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, get_flow_vlan_id(wan_key.flow_id));
        if (ret) {
            bpf_log_info("bpf_skb_vlan_push error");
        }
        ret = bpf_redirect(target_info->ifindex, 0);
        if (ret != 7) {
            bpf_log_info("bpf_redirect docker error: %d", ret);
        }
        return ret;
    }

    // bpf_log_info("wan_route_info ip: %pI4 ", target_info->gate_addr.in6_u.u6_addr8);
    // bpf_log_info("wan_route_info target_info->ifindex: %d ",target_info->ifindex);

    bool target_has_mac = target_info->has_mac;

    if (!target_has_mac) {
        return bpf_redirect(target_info->ifindex, 0);
    } else {
        struct mac_value_v6 *mac_value = bpf_map_lookup_elem(&ip_mac_v6, &target_info->gate_addr);
        if (mac_value) {
            ret = store_mac_v6(skb, &mac_value->mac, target_info->mac);
            if (!ret) {
                return bpf_redirect(target_info->ifindex, 0);
            }
        } else {
            bpf_log_info("can't find mac by: %pI6", &target_info->gate_addr);
        }
    }

    struct bpf_redir_neigh param;
    param.nh_family = AF_INET6;

    COPY_ADDR_FROM(param.ipv6_nh, target_info->gate_addr.bytes);
    ret = bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
    if (ret != 7) {
        bpf_log_info("bpf_redirect_neigh error: %d", ret);
    }
    return ret;

#undef BPF_LOG_TOPIC
}

static __always_inline int is_current_wan_packet_v6(struct __sk_buff *skb, u32 current_l3_offset,
                                                    struct route_context_v6 *context) {
#define BPF_LOG_TOPIC "is_current_wan_packet_v6"

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = skb->ingress_ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (wan_ip_info != NULL) {
        // Check if the current DST IP is the IP that enters the WAN network card
        // bpf_log_info("wan_ip_info ip: %pI6", &wan_ip_info->addr);
        if (ip_addr_equal(&wan_ip_info->addr, &context->daddr)) {
            return TC_ACT_UNSPEC;
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int search_route_in_lan_v6(struct __sk_buff *skb,
                                                  const u32 current_l3_offset,
                                                  const struct route_context_v6 *context,
                                                  u32 *flow_mark) {
#define BPF_LOG_TOPIC "search_route_in_lan_v6"
    int ret = 0;
    u32 key = WAN_CACHE;
    struct rt_cache_key_v6 search_key = {0};
    struct rt_cache_value_v6 *target = NULL;

    __builtin_memcpy(search_key.local_addr.bytes, context->saddr.bytes, 16);
    __builtin_memcpy(search_key.remote_addr.bytes, context->daddr.bytes, 16);

    // Fist WAN
    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (wan_cache) {
        target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            struct wan_ip_info_key wan_search_key = {0};
            wan_search_key.ifindex = target->ifindex;
            wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

            struct wan_ip_info_value *wan_ip_info =
                bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
            if (wan_ip_info != NULL) {
                bool target_has_mac = target->has_mac;

                // struct mac_key_v6 search_mac_key = {0};
                // COPY_ADDR_FROM(search_mac_key.addr.all, wan_ip_info->gateway.all);

                if (!target_has_mac) {
                    return bpf_redirect(target->ifindex, 0);
                } else {
                    struct mac_value_v6 *mac_value =
                        bpf_map_lookup_elem(&ip_mac_v6, &wan_ip_info->gateway);
                    if (mac_value) {
                        ret = store_mac_v6(skb, &mac_value->mac, wan_ip_info->mac);
                        if (!ret) {
                            return bpf_redirect(target->ifindex, 0);
                        }
                    } else {
                        bpf_log_info("can't find mac by: %pI6", &wan_ip_info->gateway);
                    }
                }

                struct bpf_redir_neigh param;

                param.nh_family = AF_INET6;

                COPY_ADDR_FROM(param.ipv6_nh, wan_ip_info->gateway.bits);
                ret = bpf_redirect_neigh(target->ifindex, &param, sizeof(param), 0);
                return ret;
            }
        }
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (lan_cache) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            *flow_mark = target->mark_value;
            return pick_wan_and_send_by_flow_id_v6(skb, current_l3_offset, context,
                                                   target->mark_value);
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int setting_cache_in_wan_v6(const struct route_context_v6 *context,
                                                   u32 current_l3_offset, u32 ifindex) {
#define BPF_LOG_TOPIC "setting_cache_in_wan_v6"
    struct rt_cache_key_v6 search_key = {0};
    struct rt_cache_value_v6 *target = NULL;

    u32 key = LAN_CACHE;
    search_key.local_addr = context->daddr;
    search_key.remote_addr = context->saddr;

    __builtin_memcpy(search_key.local_addr.bytes, context->saddr.bytes, 16);
    __builtin_memcpy(search_key.remote_addr.bytes, context->daddr.bytes, 16);

    void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (lan_cache != NULL) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            //     bpf_log_info("Already cached %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
            //                 search_key.remote_addr.in6_u.u6_addr8);
            // } else {
            //     bpf_log_info("Already cached %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
            //                 search_key.remote_addr.in6_u.u6_addr8);
            // }
            return TC_ACT_OK;
        }
    }

    key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (wan_cache) {
        target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            target->ifindex = ifindex;
            target->has_mac = current_l3_offset > 0;
        } else {
            struct rt_cache_value_v6 new_target_cache = {0};
            new_target_cache.ifindex = ifindex;
            new_target_cache.has_mac = current_l3_offset > 0;
            bpf_map_update_elem(wan_cache, &search_key, &new_target_cache, BPF_ANY);
        }

        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     bpf_log_info("cache %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // } else {
        //     bpf_log_info("cache %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // }
    } else {
        bpf_log_info("could not find wan_cache: %d", key);
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int setting_cache_in_lan_v6(const struct route_context_v6 *context,
                                                   u32 flow_mark) {
#define BPF_LOG_TOPIC "setting_cache_in_lan_v6"
    struct rt_cache_key_v6 search_key = {0};
    struct rt_cache_value_v6 *target = NULL;
    u32 key = WAN_CACHE;

    __builtin_memcpy(search_key.local_addr.bytes, context->saddr.bytes, 16);
    __builtin_memcpy(search_key.remote_addr.bytes, context->daddr.bytes, 16);

    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (wan_cache) {
        target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            return TC_ACT_OK;
        }
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (lan_cache) {
        target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            target->mark_value = flow_mark;
        } else {
            struct rt_cache_value_v6 new_target_cache = {0};
            new_target_cache.mark_value = flow_mark;
            bpf_map_update_elem(lan_cache, &search_key, &new_target_cache, BPF_ANY);
        }

        // if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        //     bpf_log_info("cache %pI4 -> %pI4", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // } else {
        //     bpf_log_info("cache %pI6 -> %pI6", search_key.local_addr.in6_u.u6_addr8,
        //                  search_key.remote_addr.in6_u.u6_addr8);
        // }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

#endif /* __LD_FLOW_ROUTE_v6_H__ */