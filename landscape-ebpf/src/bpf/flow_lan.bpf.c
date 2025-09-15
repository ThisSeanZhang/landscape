#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "flow_lan_share.h"
#include "land_wan_ip.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int current_eth_net_offset = 14;

// todo: 将 flow_target_info 独立出来维护
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
    __type(key, struct old_flow_cache_key);
    __type(value, struct flow_target_info);
    __uint(max_entries, 4096);
} flow_cache_map SEC(".maps");

static __always_inline int is_broadcast_mac(struct __sk_buff *skb) {
    u8 mac[6];

    // 从 skb 中 offset = 0 处读取 6 字节目的 MAC 地址
    if (bpf_skb_load_bytes(skb, 0, mac, 6) < 0) {
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

static __always_inline int get_route_context(struct __sk_buff *skb, int current_eth_net_offset,
                                             struct route_context *context) {
#define BPF_LOG_TOPIC "get_route_context"
    bool is_ipv4;
    int ret;
    if (current_eth_net_offset != 0) {
        struct ethhdr *eth;
        if (VALIDATE_READ_DATA(skb, &eth, 0, sizeof(*eth))) {
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

        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &iph, sizeof(iph));
        if (ret) {
            bpf_log_info("ipv4 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV4_TYPE;
        context->l4_protocol = iph.protocol;
        context->daddr.in6_u.u6_addr32[0] = iph.daddr;
        context->saddr.in6_u.u6_addr32[0] = iph.saddr;
    } else {
        struct ipv6hdr ip6h;
        // 读取 IPv6 头部
        ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &ip6h, sizeof(ip6h));
        if (ret) {
            bpf_log_info("ipv6 bpf_skb_load_bytes error");
            return TC_ACT_SHOT;
        }
        context->l3_protocol = LANDSCAPE_IPV6_TYPE;
        // l4 proto
        // context->l4_protocol
        COPY_ADDR_FROM(context->saddr.in6_u.u6_addr32, ip6h.saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(context->daddr.in6_u.u6_addr32, ip6h.daddr.in6_u.u6_addr32);
    }
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int current_pkg_type(struct __sk_buff *skb, int current_eth_net_offset,
                                            bool *is_ipv4_) {
    bool is_ipv4;
    if (current_eth_net_offset != 0) {
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

static __always_inline int lan_redirect_check(struct __sk_buff *skb, int current_eth_net_offset,
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

        if (current_eth_net_offset == 0 && lan_info->has_mac) {
            struct lan_mac_cache_key daddr = {0};
            daddr.l3_protocol = context->l3_protocol;
            COPY_ADDR_FROM(daddr.ip, context->daddr.in6_u.u6_addr8);
            u8 *smac = &lan_info->mac_addr;
            struct lan_mac_cache *dmac = bpf_map_lookup_elem(&ip_mac_tab, &daddr);
            bool is_ipv4 = context->l3_protocol == LANDSCAPE_IPV4_TYPE;
            if (dmac == NULL) {
                bpf_log_info("use ip: %pI6, to find mac error", &context->daddr.in6_u.u6_addr8);
                return TC_ACT_SHOT;
            }

            unsigned char ethhdr[14];
            __builtin_memcpy(ethhdr, dmac->mac, 6);
            __builtin_memcpy(ethhdr + 6, smac, 6);

            // PRINT_MAC_ADDR(ethhdr);
            // PRINT_MAC_ADDR(ethhdr + 6);

            if (is_ipv4) {
                ethhdr[12] = 0x08;
                ethhdr[13] = 0x00;
            } else {
                ethhdr[12] = 0x86;
                ethhdr[13] = 0xdd;
            }

            if (bpf_skb_change_head(skb, 14, 0)) return TC_ACT_SHOT;

            if (bpf_skb_store_bytes(skb, 0, ethhdr, sizeof(ethhdr), 0)) return TC_ACT_SHOT;

            skb->mark = 1;
            ret = bpf_redirect(lan_info->ifindex, 0);
            if (ret != 7) {
                bpf_log_info("bpf_redirect_neigh error: %d", ret);
            }

        } else {
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
        }

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

static __always_inline int is_current_wan_packet(struct __sk_buff *skb, int current_eth_net_offset,
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

static __always_inline int flow_verdict(struct __sk_buff *skb, int current_eth_net_offset,
                                        struct route_context *context, u32 *init_flow_id_) {
#define BPF_LOG_TOPIC "flow_verdict"

    struct flow_ip_cache_key cache_key = {0};
    int ret;

    // cache_key.match_key.l4_protocol; // 暂时不区分协议
    cache_key.match_key.l3_protocol = context->l3_protocol;
    cache_key.match_key.prefixlen = context->l3_protocol == LANDSCAPE_IPV4_TYPE ? 96 : 192;
    COPY_ADDR_FROM(cache_key.match_key.src_addr.all, context->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(cache_key.dst_addr.all, context->daddr.in6_u.u6_addr32);

    // 获得 flow_id
    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &cache_key.match_key);

    volatile u32 flow_id;
    if (flow_id_ptr == NULL) {
        // 查不到 flow 配置, 如果按照原逻辑直接放行 会导致默认流中, 设置了转发 DNS 查询生效
        // 但是 访问时 IP 在进行到此处时 被直接发送 就导致行为不一致
        // if (skb->ingress_ifindex != 0) {
        //     // 因为不是本机流量, 放行数据包
        //     return TC_ACT_UNSPEC;
        // }
        // 是本机路由流量 ( DNS 中的 MARK 需要按照对应的 流去处理)
        flow_id = *init_flow_id_ & 0xff;
    } else {
        flow_id = *flow_id_ptr;
    }

    // u8 flow_id_u8 = flow_id & 0xff;

    // if (flow_id != 0) {
    //     bpf_log_info("find flow_id: %d, ip: %pI4", flow_id, cache_key.match_key.src_addr.all);
    // }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key ip_trie_key = {0};
    ip_trie_key.prefixlen = context->l3_protocol == LANDSCAPE_IPV4_TYPE ? 64 : 160;
    ip_trie_key.l3_protocol = context->l3_protocol;

    COPY_ADDR_FROM(ip_trie_key.addr, cache_key.dst_addr.all);
    struct flow_ip_trie_value *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow_v_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark_value = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        if (ip_flow_mark_value != NULL) {
            flow_mark_action = ip_flow_mark_value->mark;
            priority = ip_flow_mark_value->priority;
            // bpf_log_info("find ip map mark: %d", flow_mark_action);
            // bpf_log_info("get_flow_allow_reuse_port: %d",
            // get_flow_allow_reuse_port(flow_mark_action));
        }
    } else {
        // bpf_log_info("flow_id: %d, ip map is empty", *flow_id_ptr);
    }

    struct flow_dns_match_key key = {0};
    struct flow_dns_match_value *dns_rule_value = NULL;
    key.l3_protocol = context->l3_protocol;
    COPY_ADDR_FROM(key.addr.all, cache_key.dst_addr.all);

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
        } else {
            // bpf_log_info("dns_flow_mark is none for: %pI4", &cache_key.dst_addr.ip);
        }
    } else {
        // bpf_log_info("flow_id: %d, dns map is empty", *flow_id_ptr);
    }

    // bpf_log_info("flow_id %d, flow_mark_action: %u", flow_id, flow_mark_action);
    u8 flow_action;
    struct flow_target_info *target_info;
apply_action:

    // skb->mark = flow_mark_action;
    // skb->mark = replace_flow_id(flow_mark_action, flow_id_u8);

    flow_action = get_flow_action(flow_mark_action);
    // dns_flow_id = get_flow_id(flow_mark_action);
    // bpf_log_info("dns_flow_id %d, flow_action: %d ", dns_flow_id, flow_action);
    if (flow_action == FLOW_KEEP_GOING) {
        // 无动作
        // bpf_log_info("FLOW_KEEP_GOING ip: %pI4", cache_key.dst_addr.all);
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        // bpf_log_info("FLOW_DIRECT ip: %pI4", cache_key.dst_addr.all);
        // RESET Flow ID
        // flow_id = 0;
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        // bpf_log_info("FLOW_DROP ip: %pI4", cache_key.dst_addr.all);
        return TC_ACT_SHOT;
    } else if (flow_action == FLOW_REDIRECT) {
        // bpf_log_info("FLOW_REDIRECT ip: %pI4, flow_id: %d", cache_key.dst_addr.all,
        //              dns_flow_id);
        // flow_id = dns_flow_id;
    }

keep_going:
    // if (flow_mark_action != 0) {
    //     bpf_log_info("flow_mark_action value is : %u", flow_mark_action);
    //     bpf_log_info("get_flow_id value is : %u", get_flow_id(flow_mark_action));
    //     bpf_log_info("dst ip: %pI4", cache_key.dst_addr.all);
    // }
    *init_flow_id_ = flow_mark_action;
    return TC_ACT_OK;
#undef BPF_LOG_TOPIC
}

static __always_inline int pick_wan_and_send_by_flow_id(struct __sk_buff *skb,
                                                        int current_eth_net_offset,
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
    if (current_eth_net_offset == 0 && target_info->has_mac) {
        // 当前数据包没有 mac 目标网卡有 mac
        if (prepend_dummy_mac(skb) != 0) {
            bpf_log_error("add dummy_mac fail");
            return TC_ACT_SHOT;
        }

        // 使用 bpf_redirect_neigh 转发时无需进行缩减 mac, docker 时有 mac, 所以也无需缩减 mac 地址
        // } else if (current_eth_net_offset != 0 && !target_info->has_mac) {
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

// ================================
// LAN Route Egress
// ================================
SEC("tc/egress")
int lan_route_egress(struct __sk_buff *skb) {
#define BPF_LOG_TOPIC ">> lan_route_egress"

    struct lan_route_key lan_search_key = {0};
    int ret;
    bool is_ipv4;

    if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
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

    ret = get_route_context(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    struct lan_mac_cache_key saddr = {0};
    struct lan_mac_cache cache_mac = {0};
    saddr.l3_protocol = context.l3_protocol;
    COPY_ADDR_FROM(saddr.ip, context.saddr.in6_u.u6_addr8);
    COPY_ADDR_FROM(cache_mac.mac, context.smac);
    ret = bpf_map_update_elem(&ip_mac_tab, &saddr, &cache_mac, BPF_ANY);

    // if (saddr.ip[0] == 0xfe) {
    //     if ((saddr.ip[1] & 0xc0) == 0x80) {
    //         bpf_log_info("fe80 %pI6 -> %pI6", context.saddr.in6_u.u6_addr8,
    //         context.daddr.in6_u.u6_addr8);
    //     }
    // }

    if (ret != 0) {
        bpf_log_info("cache ip: %pI6 mac error", saddr.ip);
    }

    ret = lan_redirect_check(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = flow_verdict(skb, current_eth_net_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_LAN);

    ret = pick_wan_and_send_by_flow_id(skb, current_eth_net_offset, &context, flow_mark);
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

    ret = get_route_context(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_current_wan_packet(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    ret = lan_redirect_check(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    return TC_ACT_UNSPEC;
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
        return TC_ACT_UNSPEC;
    }

    ret = get_route_context(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = is_broadcast_ip(&context);
    if (ret != TC_ACT_OK) {
        return TC_ACT_UNSPEC;
    }

    ret = lan_redirect_check(skb, current_eth_net_offset, &context);
    if (ret != TC_ACT_OK) {
        return ret;
    }
    ret = flow_verdict(skb, current_eth_net_offset, &context, &flow_mark);
    if (ret != TC_ACT_OK) {
        return ret;
    }

    barrier_var(flow_mark);
    skb->mark = replace_flow_source(flow_mark, FLOW_FROM_WAN);

    ret = pick_wan_and_send_by_flow_id(skb, current_eth_net_offset, &context, flow_mark);
    return ret;
#undef BPF_LOG_TOPIC
}

// SEC("tc/ingress")
// int flow_ingress(struct __sk_buff *skb) {
// #define BPF_LOG_TOPIC ">> flow_ingress"
//     bool is_ipv4;

//     skb->cb[4] = 111;
//     struct old_flow_cache_key cache_key = {0};
//     int ret;
//     if (current_pkg_type(skb, current_eth_net_offset, &is_ipv4) != TC_ACT_OK) {
//         return TC_ACT_UNSPEC;
//     }

//     if (current_eth_net_offset > 0) {
//         ret = bpf_skb_load_bytes(skb, 6, &cache_key.match_key.h_source,
//                                  sizeof(cache_key.match_key.h_source));
//         if (ret) {
//             bpf_log_info("mac bpf_skb_load_bytes error");
//             return TC_ACT_SHOT;
//         }
//     }

//     if (is_ipv4) {
//         ret = bpf_skb_load_bytes(skb, current_eth_net_offset + 1, &cache_key.match_key.tos,
//                                  sizeof(cache_key.match_key.tos));
//         if (ret) {
//             bpf_log_info("ipv4 bpf_skb_load_bytes error");
//             return TC_ACT_SHOT;
//         }
//     } else {
//         __u16 first_2_bytes;
//         ret =
//             bpf_skb_load_bytes(skb, current_eth_net_offset, &first_2_bytes,
//             sizeof(first_2_bytes));
//         if (ret) {
//             bpf_log_info("ipv6 bpf_skb_load_bytes error");
//             return TC_ACT_SHOT;
//         }
//         first_2_bytes = bpf_ntohs(first_2_bytes);
//         cache_key.match_key.tos = (first_2_bytes >> 4) & 0xFF;
//     }

//     // cache_key.match_key.vlan_tci = skb->vlan_present;
//     PRINT_MAC_ADDR(cache_key.match_key.h_source);
//     bpf_log_info("tos: %d", cache_key.match_key.tos);
//     bpf_log_info("vlan_tci: %d", cache_key.match_key.vlan_tci);
//     // bpf_log_info("vlan_tci: %d", skb.);
//     u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &cache_key.match_key);

//     if (flow_id_ptr == NULL || *flow_id_ptr == 0) {
//         // 查不到 flow 配置，通过使用默认路由进行处理
//         return TC_ACT_UNSPEC;
//     }

//     u32 flow_id = *flow_id_ptr;
//     skb->mark = flow_id;
//     bpf_log_info("flow_id: %d", flow_id);

//     struct bpf_fib_lookup fib_params = {0};
//     fib_params.ifindex = skb->ifindex;
//     fib_params.family = is_ipv4 ? AF_INET : AF_INET6;
//     fib_params.sport = 0;
//     fib_params.dport = 0;

//     if (is_ipv4) {
//         struct iphdr iph;

//         // 读取 IPv4 头部
//         ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &iph, sizeof(iph));
//         if (ret) {
//             bpf_log_info("ipv4 bpf_skb_load_bytes error");
//             return TC_ACT_SHOT;
//         }

//         // 填充协议与地址
//         fib_params.l4_protocol = iph.protocol;
//         fib_params.ipv4_src = iph.saddr;
//         fib_params.ipv4_dst = iph.daddr;
//     } else {
//         struct ipv6hdr ip6h;

//         // 读取 IPv6 头部
//         ret = bpf_skb_load_bytes(skb, current_eth_net_offset, &ip6h, sizeof(ip6h));
//         if (ret) {
//             bpf_log_info("ipv6 bpf_skb_load_bytes error");
//             return TC_ACT_SHOT;
//         }

//         // 填充协议与地址
//         fib_params.l4_protocol = ip6h.nexthdr;
//         COPY_ADDR_FROM(fib_params.ipv6_src, ip6h.saddr.in6_u.u6_addr32);
//         COPY_ADDR_FROM(fib_params.ipv6_dst, ip6h.daddr.in6_u.u6_addr32);
//     }

//     // print_bpf_fib_lookup(&fib_params);
//     // TODO：检查下目标 IP 是不是在黑名单中

//     // 检查缓存, 直接发往选定的网卡
//     COPY_ADDR_FROM(cache_key.src_addr.all, fib_params.ipv6_src);
//     COPY_ADDR_FROM(cache_key.dst_addr.all, fib_params.ipv6_dst);

//     struct flow_target_info *target_info;
//     target_info = bpf_map_lookup_elem(&flow_cache_map, &cache_key);
//     if (target_info == NULL) {
//         int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);

//         bpf_log_info("bpf_fib_lookup result is: %d", rc);
//         if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
//             // 缓存查询结果
//             struct flow_target_info lo_cache = {0};
//             bpf_map_update_elem(&flow_cache_map, &cache_key, &lo_cache, BPF_ANY);
//             // 发往本机的直接放行
//             return TC_ACT_UNSPEC;
//         }

//         print_bpf_fib_lookup(&fib_params);
//         // 不是发往本机的
//         // 1. 先检查有没有额外的 DNS Mark 配置

//         // 2. 根据 flow_id 检索 flow 的配置, 目前只有一个目标网卡
//         bpf_log_info("going to find target_info using flow_id: %d", flow_id);
//         target_info = bpf_map_lookup_elem(&flow_target_map, &flow_id);
//         if (target_info == NULL) {
//             bpf_log_info("can not find target_info using flow_id: %d", flow_id);
//             return TC_ACT_SHOT;
//         }
//     }

//     // 为 0 表示是本机的
//     if (target_info->ifindex == 0) {
//         return TC_ACT_UNSPEC;
//     }

//     // 缓存当前的转发结果
//     if (bpf_map_update_elem(&flow_cache_map, &cache_key, target_info, BPF_ANY)) {
//         bpf_log_info("cache fail");
//         return TC_ACT_SHOT;
//     }

//     // 依据配置发往具体的端口
//     if (current_eth_net_offset == 0 && target_info->has_mac) {
//         // 当前数据包没有 mac 对方有 mac
//         if (prepend_dummy_mac(skb) != 0) {
//             bpf_log_error("add dummy_mac fail");
//             return TC_ACT_SHOT;
//         }

//     } else if (current_eth_net_offset != 0 && !target_info->has_mac) {
//         // 当前有, 对方没有
//         // 需要 6.6 以上支持 目前暂不实现
//         return TC_ACT_SHOT;
//     }

//     if (target_info->is_docker) {
//         bpf_skb_vlan_push(skb, ETH_P_8021Q, LAND_REDIRECT_NETNS_VLAN_ID);
//         return bpf_redirect(target_info->ifindex, 0);
//     }

//     if (current_eth_net_offset != 0 && target_info->has_mac) {
//         struct bpf_fib_lookup fib_egress_param = {0};
//         fib_egress_param.ifindex = target_info->ifindex;
//         // fib_egress_param.ifindex = skb->ifindex;
//         fib_egress_param.family = is_ipv4 ? AF_INET : AF_INET6;
//         fib_egress_param.sport = 0;
//         fib_egress_param.dport = 0;

//         COPY_ADDR_FROM(fib_egress_param.ipv6_src, cache_key.src_addr.all);
//         COPY_ADDR_FROM(fib_egress_param.ipv6_dst, cache_key.dst_addr.all);

//         u32 flag = BPF_FIB_LOOKUP_OUTPUT;

//         int rcc = bpf_fib_lookup(skb, &fib_egress_param, sizeof(fib_egress_param), 0);

//         bpf_log_info("fib_egress_param result is: %d", rcc);
//         print_bpf_fib_lookup(&fib_egress_param);
//         if (rcc == 0) {
//             ret = bpf_skb_store_bytes(skb, 6, fib_egress_param.smac,
//             sizeof(fib_egress_param.smac),
//                                       0);
//             if (ret) {
//                 bpf_log_info("ret is: %d", ret);
//             }
//             ret = bpf_skb_store_bytes(skb, 0, fib_egress_param.dmac,
//             sizeof(fib_egress_param.dmac),
//                                       0);
//             if (ret) {
//                 bpf_log_info("ret2 is: %d", ret);
//             }
//         } else if (rcc == BPF_FIB_LKUP_RET_NO_NEIGH) {
//             // 发送给邻居 需要使用 bpf_redirect_neigh, 但是默认路由不属于邻居
//             struct bpf_redir_neigh param;
//             if (is_ipv4) {
//                 param.nh_family = AF_INET;
//                 param.ipv4_nh = fib_params.ipv4_dst;
//             } else {
//                 param.nh_family = AF_INET6;
//                 COPY_ADDR_FROM(param.ipv6_nh, fib_params.ipv6_dst);
//             }
//             return bpf_redirect_neigh(target_info->ifindex, &param, sizeof(param), 0);
//         } else {
//             return TC_ACT_SHOT;
//         }
//     }

//     // bpf_log_info("bpf_redirect to: %d", target_info->ifindex);
//     ret = bpf_redirect(target_info->ifindex, 0);
//     // bpf_log_info("bpf_redirect ret: %d", ret);
//     return ret;
// #undef BPF_LOG_TOPIC
// }
