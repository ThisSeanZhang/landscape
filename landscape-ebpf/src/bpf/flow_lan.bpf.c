#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "flow_lan_share.h"
#include "land_wan_ip.h"
#include "counter.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 current_l3_offset = 14;

static __always_inline int is_broadcast_mac(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "is_broadcast_mac"
    u8 mac[6];

    // 从 skb 中 offset = 0 处读取 6 字节目的 MAC 地址
    if (bpf_skb_load_bytes(skb, 0, mac, 6) < 0) {
        bpf_log_info("load bytes error drop");
        return TC_ACT_UNSPEC;
    }

    // 判断是否是广播地址 ff:ff:ff:ff:ff:ff
    bool is_broadcast = mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff &&
                        mac[4] == 0xff && mac[5] == 0xff;

    bool is_ipv6_broadcast = mac[0] == 0x33 && mac[1] == 0x33;

    if (is_broadcast || is_ipv6_broadcast) {
        return TC_ACT_UNSPEC;
    } else {
        return TC_ACT_OK;
    }
#undef BPF_LOG_TOPIC
}

static __always_inline int is_broadcast_ip(const struct route_context *context) {
    bool is_ipv6_broadcast = false;
    bool is_ipv6_locallink = false;
    bool is_ipv4_broadcast = false;

    if (context->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        __u8 first_byte = context->daddr.in6_u.u6_addr8[0];

        // IPv6 multicast ff00::/8
        if (first_byte == 0xff) {
            is_ipv6_broadcast = true;
        }

        // IPv6 link-local fe80::/10
        if (first_byte == 0xfe) {
            __u8 second_byte = context->daddr.in6_u.u6_addr8[1];
            if ((second_byte & 0xc0) == 0x80) {  // top 2 bits == 10
                is_ipv6_locallink = true;
            }
        }

    } else if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        __be32 dst = context->daddr.in6_u.u6_addr32[0];

        // 255.255.255.255 or 0.0.0.0 (network byte order)
        if (dst == bpf_htonl(0xffffffff) || dst == 0) {
            is_ipv4_broadcast = true;
        }
    }

    if (is_ipv4_broadcast || is_ipv6_broadcast || is_ipv6_locallink) {
        return TC_ACT_UNSPEC;
    } else {
        return TC_ACT_OK;
    }
}

static __always_inline int get_route_context(struct __sk_buff *skb, u32 current_l3_offset,
                                             struct route_context *context) {
#define BPF_LOG_TOPIC "get_route_context"
    bool is_ipv4;
    int ret;
    if (current_l3_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            bpf_log_info("read ethhdr drop");
            return TC_ACT_UNSPEC;
        }

        // copy mac
        COPY_ADDR_FROM(context->smac, eth->h_source);

        if (eth->h_proto == ETH_IPV4) {
            is_ipv4 = true;
        } else if (eth->h_proto == ETH_IPV6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version == 4) {
            is_ipv4 = true;
        } else if (ip_version == 6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    }

    if (is_ipv4) {
        struct iphdr iph;

        ret = bpf_skb_load_bytes(skb, current_l3_offset, &iph, sizeof(iph));
        if (ret) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV4_TYPE;
        context->l4_protocol = iph.protocol;
        context->daddr.in6_u.u6_addr32[0] = iph.daddr;
        context->saddr.in6_u.u6_addr32[0] = iph.saddr;
        
        context->l4_offset = (iph.ihl * 4) + current_l3_offset;
    } else {
        struct ipv6hdr ip6h;
        // 读取 IPv6 头部
        ret = bpf_skb_load_bytes(skb, current_l3_offset, &ip6h, sizeof(ip6h));
        if (ret) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV6_TYPE;
        // l4 proto
        context->l4_protocol = ip6h.nexthdr;
        context->l4_offset = sizeof(struct ipv6hdr) + current_l3_offset;
        COPY_ADDR_FROM(context->saddr.in6_u.u6_addr32, ip6h.saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(context->daddr.in6_u.u6_addr32, ip6h.daddr.in6_u.u6_addr32);
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int current_pkg_type(struct __sk_buff *skb, u32 current_l3_offset,
                                            bool *is_ipv4_) {
    bool is_ipv4;
    if (current_l3_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
            return TC_ACT_UNSPEC;
        }

        if (eth->h_proto == ETH_IPV4) {
            is_ipv4 = true;
        } else if (eth->h_proto == ETH_IPV6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    } else {
        u8 *p_version;
        if (VALIDATE_READ_DATA(skb, &p_version, 0, sizeof(*p_version))) {
            return TC_ACT_UNSPEC;
        }
        u8 ip_version = (*p_version) >> 4;
        if (ip_version == 4) {
            is_ipv4 = true;
        } else if (ip_version == 6) {
            is_ipv4 = false;
        } else {
            return TC_ACT_UNSPEC;
        }
    }
    *is_ipv4_ = is_ipv4;
    return TC_ACT_OK;
}

static __always_inline int lan_redirect_check(struct __sk_buff *skb, u32 current_l3_offset,
                                              struct route_context *context) {
#define BPF_LOG_TOPIC "lan_redirect_check"

    int ret;
    struct lan_route_key lan_search_key = {0};

    lan_search_key.prefixlen = 160;
    lan_search_key.l3_protocol = context->l3_protocol;
    COPY_ADDR_FROM(lan_search_key.addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8);

    struct lan_route_info *lan_info = bpf_map_lookup_elem(&rt_lan_map, &lan_search_key);

    if (lan_info != NULL) {
        // is LAN Packet, redirect to lan
        if (lan_info->ifindex == skb->ifindex) {
            // current iface
            return TC_ACT_UNSPEC;
        }

        if (ip_addr_equal(&lan_info->addr, &context->daddr)) {
            return TC_ACT_UNSPEC;
        }

        if (current_l3_offset == 0 && lan_info->has_mac) {
            bool is_ipv4 = context->l3_protocol == LANDSCAPE_IPV4_TYPE;
            unsigned char ethhdr[14];
            if (is_ipv4) {
                ethhdr[12] = 0x08;
                ethhdr[13] = 0x00;
            } else {
                ethhdr[12] = 0x86;
                ethhdr[13] = 0xdd;
            }
            if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;

            if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;
        }
        struct bpf_redir_neigh param;
        if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
            param.nh_family = AF_INET;
        } else {
            param.nh_family = AF_INET6;
        }

        COPY_ADDR_FROM(param.ipv6_nh, lan_search_key.addr.in6_u.u6_addr32);
        ret = bpf_redirect_neigh(lan_info->ifindex, &param, sizeof(param), 0);
        // bpf_log_info("lan_info->ifindex:  %d", lan_info->ifindex);
        // bpf_log_info("is_ipv4:  %d", is_ipv4);
        // bpf_log_info("bpf_redirect_neigh ip:  %pI6", lan_search_key.addr.in6_u.u6_addr8);
        if (ret != 7) {
            bpf_log_info("bpf_redirect_neigh error: %d", ret);
        }
        // bpf_log_info("bpf_redirect_neigh result: %d", ret);

        return ret;
    }

    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[0]);
    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[1]);
    // bpf_log_info("lan_info pad: %d", lan_search_key._pad[2]);
    // bpf_log_info("lan_info prefixlen: %d", lan_search_key.prefixlen);
    // bpf_log_info("lan_info l3_protocol: %d", lan_search_key.l3_protocol);
    // bpf_log_info("lan_info ip: %pI4", lan_search_key.addr.in6_u.u6_addr8);

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int is_current_wan_packet(struct __sk_buff *skb, u32 current_l3_offset,
                                                 struct route_context *context) {
#define BPF_LOG_TOPIC "is_current_wan_packet"

    if (context->l3_protocol == LANDSCAPE_IPV6_TYPE) {
        return TC_ACT_OK;
    }

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = skb->ingress_ifindex;
    wan_search_key.l3_protocol = context->l3_protocol;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ipv4_binding, &wan_search_key);
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

static __always_inline int flow_verdict(struct __sk_buff *skb, u32 current_l3_offset,
                                        struct route_context *context, u32 *init_flow_id_) {
#define BPF_LOG_TOPIC "flow_verdict"

    int ret;
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (match_flow_id(skb, current_l3_offset, context, &flow_id)) {
        return TC_ACT_SHOT;
    }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key ip_trie_key = {0};
    ip_trie_key.prefixlen = context->l3_protocol == LANDSCAPE_IPV4_TYPE ? 64 : 160;
    ip_trie_key.l3_protocol = context->l3_protocol;
    COPY_ADDR_FROM(ip_trie_key.addr, context->daddr.in6_u.u6_addr8);

    struct flow_ip_trie_value *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow_v_ip_map, &flow_id);
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

    struct flow_dns_match_key key = {0};
    struct flow_dns_match_value *dns_rule_value = NULL;
    key.l3_protocol = context->l3_protocol;
    COPY_ADDR_FROM(key.addr.all, context->daddr.in6_u.u6_addr32);

    // 查询 DNS 配置信息，查看是否有转发流的配置
    void *dns_rules_map = bpf_map_lookup_elem(&flow_v_dns_map, &flow_id);
    if (dns_rules_map != NULL) {
    }

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

static __always_inline int pick_wan_and_send_by_flow_id(struct __sk_buff *skb,
                                                        u32 current_l3_offset,
                                                        struct route_context *context,
                                                        const u32 flow_id) {
#define BPF_LOG_TOPIC "pick_wan_and_send_by_flow_id"

    int ret;
    struct route_target_key wan_key = {0};

    wan_key.flow_id = get_flow_id(flow_id);
    wan_key.l3_protocol = context->l3_protocol;

    struct route_target_info *target_info = bpf_map_lookup_elem(&rt_target_map, &wan_key);

    // 找不到转发的 target 按照原有计划进行处理
    if (target_info == NULL) {
        if (wan_key.flow_id == 0) {
            // Default flow PASS
            return TC_ACT_UNSPEC;
        } else {
            bpf_log_info("DROP flow_id: %d, l3_protocol: %d", wan_key.flow_id, wan_key.l3_protocol);
            // Other DROP
            return TC_ACT_SHOT;
        }
    }

    if (target_info->ifindex == skb->ifindex) {
        // Belongs to the current ifindex No redirection required
        return TC_ACT_UNSPEC;
    }

    // 依据配置发往具体的网卡， 检查 MAC 地址
    if (current_l3_offset == 0 && target_info->has_mac) {
        // 当前数据包没有 mac 目标网卡有 mac
        if (prepend_dummy_mac(skb) != 0) {
            bpf_log_error("add dummy_mac fail");
            return TC_ACT_SHOT;
        }

        // 使用 bpf_redirect_neigh 转发时无需进行缩减 mac, docker 时有 mac, 所以也无需缩减 mac 地址
        // } else if (current_l3_offset != 0 && !target_info->has_mac) {
        //     // 当前有, 目标网卡没有
        //     int ret = bpf_skb_adjust_room(skb, -14, BPF_ADJ_ROOM_MAC, 0);
        //     if (ret < 0) {
        //         return TC_ACT_SHOT;
        // }
    }

    if (target_info->is_docker) {
        ret = bpf_skb_vlan_push(skb, ETH_P_8021Q, LAND_REDIRECT_NETNS_VLAN_ID);
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

    struct bpf_redir_neigh param;
    if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
        param.nh_family = AF_INET;
    } else {
        param.nh_family = AF_INET6;
    }

    COPY_ADDR_FROM(param.ipv6_nh, target_info->gate_addr.in6_u.u6_addr32);
    ret = bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
    if (ret != 7) {
        bpf_log_info("bpf_redirect_neigh error: %d", ret);
    }
    return ret;

#undef BPF_LOG_TOPIC
}

static __always_inline int search_route_in_lan(struct __sk_buff *skb, const u32 current_l3_offset,
                                               const struct route_context *context,
                                               u32 *flow_mark) {
#define BPF_LOG_TOPIC "search_route_in_lan"
    int ret = 0;
    u32 key = WAN_CACHE;
    struct rt_cache_key search_key = {0};
    COPY_ADDR_FROM(search_key.local_addr.in6_u.u6_addr8, context->saddr.in6_u.u6_addr8);
    COPY_ADDR_FROM(search_key.remote_addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8);

    // Fist WAN
    void *wan_cache = bpf_map_lookup_elem(&rt_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value *target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            struct wan_ip_info_key wan_search_key = {0};
            wan_search_key.ifindex = target->ifindex;
            wan_search_key.l3_protocol = context->l3_protocol;

            struct wan_ip_info_value *wan_ip_info =
                bpf_map_lookup_elem(&wan_ipv4_binding, &wan_search_key);
            if (wan_ip_info != NULL) {
                struct bpf_redir_neigh param;
                if (context->l3_protocol == LANDSCAPE_IPV4_TYPE) {
                    param.nh_family = AF_INET;
                } else {
                    param.nh_family = AF_INET6;
                }

                COPY_ADDR_FROM(param.ipv6_nh, wan_ip_info->gateway.bits);
                ret = bpf_redirect_neigh(target->ifindex, &param, sizeof(param), 0);
                return ret;
            }
        }
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt_cache_map, &key);
    if (lan_cache) {
        struct rt_cache_value *target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            *flow_mark = target->mark_value;
            return pick_wan_and_send_by_flow_id(skb, current_l3_offset, context,
                                                target->mark_value);
        }
    }

    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

// ================================
// LAN Route Egress
// ================================
SEC("tc/egress")
int lan_route_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">> lan_route_egress"

    struct lan_route_key lan_search_key = {0};
    int ret;
    bool is_ipv4;

    if (current_pkg_type(skb, current_l3_offset, &is_ipv4) != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

// ================================
// LAN Route Ingress
// ================================
SEC("tc/ingress")
int lan_route_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "lan_route_ingress"
    // bool is_ipv4;

    int ret;
    u32 flow_mark = skb->mark;
    struct route_context context = {0};

    ret = is_broadcast_mac(skb);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = get_route_context(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    if (context.l4_protocol == NEXTHDR_ICMP) {
        struct icmphdr *icmph;
        if (!VALIDATE_READ_DATA(skb, &icmph, context.l4_offset, sizeof(struct icmphdr))) {
            if (icmph->type == 128) {
                u32 key = 0;
                u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                if (count) {
                    __sync_fetch_and_add(count, 1);
                }
            }
        }
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    // if (saddr.ip[0] == 0xfe) {
    //     if ((saddr.ip[1] & 0xc0) == 0x80) {
    //         bpf_log_info("fe80 %pI6 -> %pI6", context.saddr.in6_u.u6_addr8,
    //         context.daddr.in6_u.u6_addr8);
    //     }
    // }

    ret = search_route_in_lan(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);
        return ret;
    }

    ret = lan_redirect_check(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);

    ret = pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);

    if (ret == TC_ACT_REDIRECT) {
        setting_cache_in_lan(&context, flow_mark);
        
        if (context.l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, context.l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 128) {
                    u32 key = 1;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
    }
    
    
    if (context.l4_protocol == NEXTHDR_ICMP) {
        struct icmphdr *icmph;
        if (!VALIDATE_READ_DATA(skb, &icmph, context.l4_offset, sizeof(struct icmphdr))) {
            if (icmph->type == 128) {
                u32 key = 2;
                u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                if (count) {
                    __sync_fetch_and_add(count, 1);
                }
            }
        }
    }
    return ret;
#undef BPF_LOG_TOPIC
}

// ================================
// WAN Route Ingress
// ================================
SEC("tc/ingress")
int wan_route_ingress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "wan_route_ingress"
    bool is_ipv4;
    int ret;
    struct route_context context = {0};

    ret = is_broadcast_mac(skb);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = get_route_context(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_current_wan_packet(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = lan_redirect_check(skb, current_l3_offset, &context);
    if (ret == TC_ACT_REDIRECT) {
        u8 mark = get_cache_mask(skb->mark);
        if (mark == INGRESS_STATIC_MARK) {
            // bpf_log_info("get wan ingress mark: %u", mark);
            setting_cache_in_wan(&context, skb->ifindex);
        }
    }

    return ret == TC_ACT_OK ? TC_ACT_UNSPEC : ret;
#undef BPF_LOG_TOPIC
}

// ================================
// WAN Route Egress
// ================================
SEC("tc/egress")
int wan_route_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC "wan_route_egress"
    int ret;
    u32 flow_mark = skb->mark;
    struct route_context context = {0};

    ret = is_broadcast_mac(skb);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    if (skb->ingress_ifindex != 0) {
        // 端口转发数据, 相对于是已经决定使用这个出口, 所以直接发送
        
        if (context.l4_protocol == NEXTHDR_ICMP) {
            struct icmphdr *icmph;
            if (!VALIDATE_READ_DATA(skb, &icmph, context.l4_offset, sizeof(struct icmphdr))) {
                if (icmph->type == 128) {
                    u32 key = 3;
                    u64 *count = bpf_map_lookup_elem(&debug_counter, &key);
                    if (count) {
                        __sync_fetch_and_add(count, 1);
                    }
                }
            }
        }
        return TC_ACT_UNSPEC;
    }

    ret = get_route_context(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = lan_redirect_check(skb, current_l3_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    ret = flow_verdict(skb, current_l3_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_WAN);

    ret = pick_wan_and_send_by_flow_id(skb, current_l3_offset, &context, flow_mark);
    return ret;
#undef BPF_LOG_TOPIC
}
