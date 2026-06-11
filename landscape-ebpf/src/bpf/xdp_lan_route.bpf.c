#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "land_wan_ip.h"

#include "chain/xdp_meta.h"
#include "chain/redirect_able.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

#include "route/route_index.h"
#include "route/route_maps_v4.h"
#include "route/route_maps_v6.h"

#include "flow_match.h"
#include "neigh_ip.h"

char LICENSE[] SEC("license") = "GPL";

// ── Packet reading (shared with xdp_wan_route) ──

static __always_inline int xdp_read_ipv4(struct xdp_md *ctx, struct route_context_v4 *context) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != ETH_IPV4) return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_DROP;

    context->saddr = iph->saddr;
    context->daddr = iph->daddr;
    return 0;
}

static __always_inline int xdp_read_ipv6(struct xdp_md *ctx, struct route_context_v6 *context) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != ETH_IPV6) return XDP_PASS;

    ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) return XDP_DROP;

    COPY_ADDR_FROM(context->saddr.all, ip6h->saddr.in6_u.u6_addr32);
    COPY_ADDR_FROM(context->daddr.all, ip6h->daddr.in6_u.u6_addr32);
    return 0;
}

// ── Forwarding checks ──

static __always_inline int xdp_should_forward_v4(const struct route_context_v4 *context) {
    return should_not_forward(context->daddr) ? XDP_PASS : 0;
}

static __always_inline int xdp_should_forward_v6(const struct route_context_v6 *context) {
    return is_broadcast_ip6(context->daddr.bytes) == TC_ACT_UNSPEC ? XDP_PASS : 0;
}

// ── XDP flow_id matching (MAC at eth->h_source, no current_l3_offset check needed) ──

static __always_inline int xdp_match_flow_id_v4(struct xdp_md *ctx, __be32 saddr,
                                                u32 *default_flow_id_) {
    struct flow_match_key match_key = {};
    u32 ret_flow_id = *default_flow_id_;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    __builtin_memcpy(match_key.mac.mac, eth->h_source, 6);
    match_key.prefixlen = FLOW_MAC_MATCH_LEN;
    match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    match_key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    match_key.prefixlen = FLOW_IP_IPV4_MATCH_LEN;
    match_key.src_addr.ip = saddr;

    flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    *default_flow_id_ = ret_flow_id;
    return 0;
}

static __always_inline int xdp_match_flow_id_v6(struct xdp_md *ctx, const union u_inet6_addr *saddr,
                                                u32 *default_flow_id_) {
    struct flow_match_key match_key = {};
    u32 ret_flow_id = *default_flow_id_;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    __builtin_memcpy(match_key.mac.mac, eth->h_source, 6);
    match_key.prefixlen = FLOW_MAC_MATCH_LEN;
    match_key.is_match_ip = FLOW_ENTRY_MODE_MAC;

    u32 *flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    match_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    match_key.is_match_ip = FLOW_ENTRY_MODE_IP;
    match_key.prefixlen = FLOW_IP_IPV6_MATCH_LEN;
    COPY_ADDR_FROM(match_key.src_addr.all, saddr->bytes);

    flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    *default_flow_id_ = ret_flow_id;
    return 0;
}

// ── XDP-adapted flow_verdict ──

static __always_inline int xdp_flow_verdict_v4(struct xdp_md *ctx,
                                               const struct route_context_v4 *context,
                                               u32 *init_flow_id_) {
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (xdp_match_flow_id_v4(ctx, context->saddr, (u32 *)&flow_id)) {
        return XDP_DROP;
    }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key_v4 ip_trie_key = {.prefixlen = 32, .addr = context->daddr};
    struct flow_ip_trie_value_v4 *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow4_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark_value = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        if (ip_flow_mark_value != NULL) {
            flow_mark_action = ip_flow_mark_value->mark;
            priority = ip_flow_mark_value->priority;
        }
    }

    struct flow_dns_match_key_v4 dns_key = {.addr = context->daddr};
    struct flow_dns_match_value_v4 *dns_rule_value = NULL;
    void *dns_rules_map = bpf_map_lookup_elem(&flow4_dns_map, &flow_id);
    if (dns_rules_map != NULL) {
        dns_rule_value = bpf_map_lookup_elem(dns_rules_map, &dns_key);
        if (dns_rule_value != NULL && dns_rule_value->priority <= priority) {
            flow_mark_action = dns_rule_value->mark;
            priority = dns_rule_value->priority;
        }
    }

    flow_action = get_flow_action(flow_mark_action);
    if (flow_action == FLOW_KEEP_GOING) {
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        return XDP_DROP;
    }

keep_going:
    *init_flow_id_ = flow_mark_action;
    return 0;
}

static __always_inline int xdp_flow_verdict_v6(struct xdp_md *ctx,
                                               const struct route_context_v6 *context,
                                               u32 *init_flow_id_) {
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (xdp_match_flow_id_v6(ctx, &context->saddr, (u32 *)&flow_id)) {
        return XDP_DROP;
    }

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key_v6 ip_trie_key = {.prefixlen = 128};
    COPY_ADDR_FROM(ip_trie_key.addr.bytes, context->daddr.bytes);
    struct flow_ip_trie_value_v6 *ip_flow_mark_value = NULL;
    void *ip_rules_map = bpf_map_lookup_elem(&flow6_ip_map, &flow_id);
    if (ip_rules_map != NULL) {
        ip_flow_mark_value = bpf_map_lookup_elem(ip_rules_map, &ip_trie_key);
        if (ip_flow_mark_value != NULL) {
            flow_mark_action = ip_flow_mark_value->mark;
            priority = ip_flow_mark_value->priority;
        }
    }

    struct flow_dns_match_key_v6 dns_key = {};
    dns_key.addr = context->daddr;
    struct flow_dns_match_value_v6 *dns_rule_value = NULL;
    void *dns_rules_map = bpf_map_lookup_elem(&flow6_dns_map, &flow_id);
    if (dns_rules_map != NULL) {
        dns_rule_value = bpf_map_lookup_elem(dns_rules_map, &dns_key);
        if (dns_rule_value != NULL && dns_rule_value->priority <= priority) {
            flow_mark_action = dns_rule_value->mark;
            priority = dns_rule_value->priority;
        }
    }

    flow_action = get_flow_action(flow_mark_action);
    if (flow_action == FLOW_KEEP_GOING) {
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        return XDP_DROP;
    }

keep_going:
    *init_flow_id_ = flow_mark_action;
    return 0;
}

// ── XDP cache-pick-wan: pickup + write cache ──

static __always_inline int xdp_cache_pick_wan_v4(struct xdp_md *ctx,
                                                 const struct route_context_v4 *context,
                                                 const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route_target_slot_key_v4 slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route_target_slot_v4(context->daddr),
    };
    struct route_target_info_v4 *info = bpf_map_lookup_elem(&rt4_target_slot_map, &slot_key);
    if (info == NULL) {
        if (resolved_flow_id == 0) return 0;
        return XDP_DROP;
    }

    if (info->ifindex == ctx->ingress_ifindex) return 0;

    if (info->has_mac) {
        struct mac_value_v4 *mac_val = bpf_map_lookup_elem(&ip_mac_v4, &info->gate_addr);
        if (mac_val) {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_DROP;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, info->mac, 6);
        }
    }

    bool already_cached = false;
    struct rt_cache_key_v4 cache_key = {.local_addr = context->saddr,
                                        .remote_addr = context->daddr};

    u32 wan_key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &wan_key);
    if (wan_cache) {
        if (bpf_map_lookup_elem(wan_cache, &cache_key) != NULL) already_cached = true;
    }

    if (!already_cached) {
        u32 lan_key = LAN_CACHE;
        void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &lan_key);
        if (lan_cache) {
            struct rt_cache_value_v4 *entry = bpf_map_lookup_elem(lan_cache, &cache_key);
            if (entry) {
                entry->mark_value = flow_id;
                entry->ifindex = info->ifindex;
                entry->has_mac = info->has_mac;
                entry->is_docker = info->is_docker;
                entry->xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                entry->gate_addr = info->gate_addr;
                __builtin_memcpy(entry->mac, info->mac, 6);
            } else {
                struct rt_cache_value_v4 new_entry = {};
                new_entry.mark_value = flow_id;
                new_entry.ifindex = info->ifindex;
                new_entry.has_mac = info->has_mac;
                new_entry.is_docker = info->is_docker;
                new_entry.xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                new_entry.gate_addr = info->gate_addr;
                __builtin_memcpy(new_entry.mac, info->mac, 6);
                bpf_map_update_elem(lan_cache, &cache_key, &new_entry, BPF_ANY);
            }
        }
    }

    if (info->is_docker) {
        xdp_set_docker_meta(ctx, flow_id, info->ifindex);
        return XDP_PASS;
    }
    if (!xdp_redirect_target_able(info->ifindex)) {
        int ret = xdp_set_tc_redirect_meta(ctx, flow_id, info->ifindex);
        if (ret) return XDP_DROP;
        return XDP_PASS;
    }

    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);
    meta.mark = flow_id;
    meta.target_ifindex = info->ifindex;
    xdp_set_meta(ctx, &meta);

    // bpf_printk("[lan_route] cache_pick_wan_v4 tailcall to ifindex=%u", info->ifindex);
    bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, info->ifindex);
    bpf_printk("[lan_route] cache_pick_wan_v4 tailcall FAILED for ifindex=%u", info->ifindex);
    return XDP_DROP;
}

static __always_inline int xdp_cache_pick_wan_v6(struct xdp_md *ctx,
                                                 const struct route_context_v6 *context,
                                                 const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);

    struct route_target_slot_key_v6 slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route_target_slot_v6(&context->daddr),
    };
    struct route_target_info_v6 *info = bpf_map_lookup_elem(&rt6_target_slot_map, &slot_key);
    if (info == NULL) {
        if (resolved_flow_id == 0) return 0;
        return XDP_DROP;
    }

    if (info->ifindex == ctx->ingress_ifindex) return 0;

    if (info->has_mac) {
        struct mac_value_v6 *mac_val = bpf_map_lookup_elem(&ip_mac_v6, &info->gate_addr);
        if (mac_val) {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_DROP;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, info->mac, 6);
        }
    }

    bool already_cached = false;
    struct rt_cache_key_v6 cache_key = {};
    __builtin_memcpy(cache_key.local_addr.bytes, context->saddr.bytes, 16);
    __builtin_memcpy(cache_key.remote_addr.bytes, context->daddr.bytes, 16);

    u32 wan_key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &wan_key);
    if (wan_cache) {
        if (bpf_map_lookup_elem(wan_cache, &cache_key) != NULL) already_cached = true;
    }

    if (!already_cached) {
        u32 lan_key = LAN_CACHE;
        void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &lan_key);
        if (lan_cache) {
            struct rt_cache_value_v6 *entry = bpf_map_lookup_elem(lan_cache, &cache_key);
            if (entry) {
                entry->mark_value = flow_id;
                entry->ifindex = info->ifindex;
                entry->has_mac = info->has_mac;
                entry->is_docker = info->is_docker;
                entry->xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                __builtin_memcpy(entry->gate_addr.bytes, info->gate_addr.bytes, 16);
                __builtin_memcpy(entry->mac, info->mac, 6);
            } else {
                struct rt_cache_value_v6 new_entry = {};
                new_entry.mark_value = flow_id;
                new_entry.ifindex = info->ifindex;
                new_entry.has_mac = info->has_mac;
                new_entry.is_docker = info->is_docker;
                new_entry.xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                __builtin_memcpy(new_entry.gate_addr.bytes, info->gate_addr.bytes, 16);
                __builtin_memcpy(new_entry.mac, info->mac, 6);
                bpf_map_update_elem(lan_cache, &cache_key, &new_entry, BPF_ANY);
            }
        }
    }

    if (info->is_docker) {
        xdp_set_docker_meta(ctx, flow_id, info->ifindex);
        return XDP_PASS;
    }
    if (!xdp_redirect_target_able(info->ifindex)) {
        int ret = xdp_set_tc_redirect_meta(ctx, flow_id, info->ifindex);
        if (ret) return XDP_DROP;
        return XDP_PASS;
    }

    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);
    meta.mark = flow_id;
    meta.target_ifindex = info->ifindex;
    xdp_set_meta(ctx, &meta);

    // bpf_printk("[lan_route] cache_pick_wan_v6 tailcall to ifindex=%u", info->ifindex);
    bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, info->ifindex);
    bpf_printk("[lan_route] cache_pick_wan_v6 tailcall FAILED for ifindex=%u", info->ifindex);
    return XDP_DROP;
}

// ── LAN→LAN redirect (shared with xdp_wan_route) ──

static __always_inline int xdp_lan_redirect_v4(struct xdp_md *ctx,
                                               struct route_context_v4 *context) {
#define BPF_LOG_TOPIC "xdp_lan_redirect_v4"
    struct lan_route_key_v4 key = {.prefixlen = 32, .addr = context->daddr};
    struct mac_key_v4 mac_key = {.addr = context->daddr};
    struct mac_value_v4 *mac_val;
    int ret;

    struct lan_route_info_v4 *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &key);
    if (lan_info == NULL) return 0;

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        if (lan_info->addr == context->daddr) return XDP_PASS;
        if (lan_info->has_mac) {
            mac_val = bpf_map_lookup_elem(&ip_mac_v4, &mac_key);
            if (mac_val) {
                void *data = (void *)(long)ctx->data;
                void *data_end = (void *)(long)ctx->data_end;
                struct ethhdr *eth = data;
                if ((void *)(eth + 1) > data_end) return XDP_PASS;
                __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            }
        }
        if (!xdp_redirect_target_able(lan_info->ifindex)) {
            int ret = xdp_set_tc_redirect_meta(ctx, 0, lan_info->ifindex);
            if (ret) return XDP_DROP;
            return XDP_PASS;
        }
        struct xdp_pipe_meta meta = {};
        meta.target_ifindex = lan_info->ifindex;
        meta.mark = 0;
        xdp_set_meta(ctx, &meta);
        bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, lan_info->ifindex);
        return XDP_DROP;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) return XDP_PASS;
    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) return XDP_PASS;

    if (lan_info->has_mac) {
        mac_key.addr = lan_info->route_type == ROUTE_TYPE_NEXTHOP ? lan_info->addr : context->daddr;
        mac_val = bpf_map_lookup_elem(&ip_mac_v4, &mac_key);
        if (mac_val) {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            ret = xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
            // ld_bpf_log("bpf_redirect 1 %pI4 -> %pI4 idx: %d ret: %d", &context->saddr,
            //            &context->daddr, lan_info->ifindex, ret);
            return ret;
        }

        struct bpf_fib_lookup fib = {};
        fib.family = AF_INET;
        fib.tot_len = sizeof(struct iphdr);
        fib.ipv4_src = context->saddr;
        fib.ipv4_dst = mac_key.addr;
        fib.ifindex = ctx->ingress_ifindex;

        int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            if (fib.ifindex == ctx->ingress_ifindex) return XDP_PASS;

            struct mac_value_v4 new_val = {.ifindex = lan_info->ifindex, .proto = ETH_IPV4};
            __builtin_memcpy(new_val.mac, fib.dmac, 6);
            __builtin_memcpy(new_val.dev_mac, lan_info->mac_addr, 6);
            bpf_map_update_elem(&ip_mac_v4, &mac_key, &new_val, BPF_ANY);

            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, fib.dmac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            // ld_bpf_log("bpf_redirect 2");
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
        }
        return 0;
    }

    // ld_bpf_log("bpf_redirect 3");
    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
#undef BPF_LOG_TOPIC
}

static __always_inline int xdp_lan_redirect_v6(struct xdp_md *ctx,
                                               struct route_context_v6 *context) {
    struct lan_route_key_v6 key = {.prefixlen = 128};
    struct mac_value_v6 *mac_val;
    COPY_ADDR_FROM(key.addr.bytes, context->daddr.bytes);

    struct lan_route_info_v6 *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &key);
    if (lan_info == NULL) return 0;

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        if (ip_addr_equal_in6(&lan_info->addr, &context->daddr)) return XDP_PASS;
        if (lan_info->has_mac) {
            struct mac_key_v6 dst_key = {};
            COPY_ADDR_FROM(dst_key.addr.all, context->daddr.all);
            mac_val = bpf_map_lookup_elem(&ip_mac_v6, &dst_key);
            if (mac_val) {
                void *data = (void *)(long)ctx->data;
                void *data_end = (void *)(long)ctx->data_end;
                struct ethhdr *eth = data;
                if ((void *)(eth + 1) > data_end) return XDP_PASS;
                __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            }
        }
        if (!xdp_redirect_target_able(lan_info->ifindex)) {
            int ret = xdp_set_tc_redirect_meta(ctx, 0, lan_info->ifindex);
            if (ret) return XDP_DROP;
            return XDP_PASS;
        }
        struct xdp_pipe_meta meta = {};
        meta.target_ifindex = lan_info->ifindex;
        meta.mark = 0;
        xdp_set_meta(ctx, &meta);
        bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, lan_info->ifindex);
        return XDP_DROP;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) return XDP_PASS;
    if (lan_info->route_type == ROUTE_TYPE_LAN &&
        ip_addr_equal_in6(&lan_info->addr, &context->daddr))
        return XDP_PASS;

    if (lan_info->has_mac) {
        struct mac_key_v6 hop_key = {};
        COPY_ADDR_FROM(hop_key.addr.all, lan_info->route_type == ROUTE_TYPE_NEXTHOP
                                             ? lan_info->addr.all
                                             : context->daddr.all);
        mac_val = bpf_map_lookup_elem(&ip_mac_v6, &hop_key);
        if (mac_val) {
            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
        }

        struct bpf_fib_lookup fib = {};
        fib.family = AF_INET6;
        fib.tot_len = sizeof(struct ipv6hdr);
        COPY_ADDR_FROM(fib.ipv6_src, context->saddr.all);
        COPY_ADDR_FROM(fib.ipv6_dst, hop_key.addr.all);
        fib.ifindex = ctx->ingress_ifindex;

        int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            if (fib.ifindex == ctx->ingress_ifindex) return XDP_PASS;

            struct mac_value_v6 new_val = {.ifindex = lan_info->ifindex, .proto = ETH_IPV6};
            __builtin_memcpy(new_val.mac, fib.dmac, 6);
            __builtin_memcpy(new_val.dev_mac, lan_info->mac_addr, 6);
            bpf_map_update_elem(&ip_mac_v6, &hop_key, &new_val, BPF_ANY);

            void *data = (void *)(long)ctx->data;
            void *data_end = (void *)(long)ctx->data_end;
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, fib.dmac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
        }
        return 0;
    }

    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0);
}

// ── search_route_in_lan: cache lookup → tailcall to LAN→WAN chain ──

static __always_inline int xdp_search_route_in_lan_v4(struct xdp_md *ctx,
                                                      const struct route_context_v4 *context,
                                                      u32 *flow_mark) {
    struct rt_cache_key_v4 search_key = {.local_addr = context->saddr,
                                         .remote_addr = context->daddr};
    u32 key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value_v4 *target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            bpf_printk("[wan_cache_r] v4 HIT src=%pI4 dst=%pI4 ifindex=%u has_mac=%u",
                       &context->saddr, &context->daddr, target->ifindex, target->has_mac);
            if (target->is_docker) {
                xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                return XDP_PASS;
            }
            if (!target->xdp_redirect_able) {
                int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex);
                if (ret) return XDP_DROP;
                return XDP_PASS;
            }
            struct wan_ip_info_key wan_key = {.ifindex = target->ifindex,
                                              .l3_protocol = LANDSCAPE_IPV4_TYPE};
            struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
            if (wan_info != NULL) {
                if (target->has_mac) {
                    struct mac_value_v4 *mac_val =
                        bpf_map_lookup_elem(&ip_mac_v4, &search_key.remote_addr);
                    if (!mac_val) {
                        mac_val = bpf_map_lookup_elem(&ip_mac_v4, &wan_info->gateway.ip);
                    }
                    if (mac_val) {
                        // bpf_printk("[wan_cache_r] v4 MAC dst=%pM src=%pM", mac_val->mac,
                        //            mac_val->dev_mac);
                        void *data = (void *)(long)ctx->data;
                        void *data_end = (void *)(long)ctx->data_end;
                        struct ethhdr *eth = data;
                        if ((void *)(eth + 1) > data_end) return XDP_DROP;
                        __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                        __builtin_memcpy(eth->h_source, mac_val->dev_mac, 6);
                    }
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                // bpf_printk("[lan_route] search_lan_v4 WAN-hit tailcall to ifindex=%u",
                //            target->ifindex);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->ifindex);
                bpf_printk("[lan_route] search_lan_v4 WAN-hit tailcall FAILED ifindex=%u",
                           target->ifindex);
                return XDP_DROP;
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
                if (target->is_docker) {
                    xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                    return XDP_PASS;
                }
                if (!target->xdp_redirect_able) {
                    int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex);
                    if (ret) return XDP_DROP;
                    return XDP_PASS;
                }
                if (target->has_mac) {
                    struct mac_value_v4 *mac_val =
                        bpf_map_lookup_elem(&ip_mac_v4, &target->gate_addr);
                    if (mac_val) {
                        void *data = (void *)(long)ctx->data;
                        void *data_end = (void *)(long)ctx->data_end;
                        struct ethhdr *eth = data;
                        if ((void *)(eth + 1) > data_end) return XDP_DROP;
                        __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                        __builtin_memcpy(eth->h_source, target->mac, 6);
                    }
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                // bpf_printk("[lan_route] search_lan_v4 LAN-hit tailcall to ifindex=%u",
                //            target->ifindex);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->ifindex);
                bpf_printk("[lan_route] search_lan_v4 LAN-hit tailcall FAILED ifindex=%u",
                           target->ifindex);
                return XDP_DROP;
            }
            return xdp_cache_pick_wan_v4(ctx, context, target->mark_value);
        }
    }
    return 0;
}

static __always_inline int xdp_search_route_in_lan_v6(struct xdp_md *ctx,
                                                      const struct route_context_v6 *context,
                                                      u32 *flow_mark) {
    struct rt_cache_key_v6 search_key = {};
    __builtin_memcpy(search_key.local_addr.bytes, context->saddr.bytes, 16);
    __builtin_memcpy(search_key.remote_addr.bytes, context->daddr.bytes, 16);

    u32 key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value_v6 *target = bpf_map_lookup_elem(wan_cache, &search_key);
        if (target) {
            if (target->is_docker) {
                xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                return XDP_PASS;
            }
            if (!target->xdp_redirect_able) {
                int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex);
                if (ret) return XDP_DROP;
                return XDP_PASS;
            }
            bpf_printk("[wan_cache_r] v6 HIT src=%pI6c dst=%pI6c ifindex=%u has_mac=%u",
                       &context->saddr, &context->daddr, target->ifindex, target->has_mac);
            struct wan_ip_info_key wan_key = {.ifindex = target->ifindex,
                                              .l3_protocol = LANDSCAPE_IPV6_TYPE};
            struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
            if (wan_info != NULL) {
                if (target->has_mac) {
                    struct mac_key_v6 mac_key = {};
                    COPY_ADDR_FROM(mac_key.addr.bytes, search_key.remote_addr.bytes);
                    struct mac_value_v6 *mac_val = bpf_map_lookup_elem(&ip_mac_v6, &mac_key);
                    if (!mac_val) {
                        COPY_ADDR_FROM(mac_key.addr.bytes, wan_info->gateway.bits);
                        mac_val = bpf_map_lookup_elem(&ip_mac_v6, &mac_key);
                    }
                    if (mac_val) {
                        // bpf_printk("[wan_cache_r] v6 MAC dst=%pM src=%pM", mac_val->mac,
                        //            mac_val->dev_mac);
                        void *data = (void *)(long)ctx->data;
                        void *data_end = (void *)(long)ctx->data_end;
                        struct ethhdr *eth = data;
                        if ((void *)(eth + 1) > data_end) return XDP_DROP;
                        __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                        __builtin_memcpy(eth->h_source, mac_val->dev_mac, 6);
                    }
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                // bpf_printk("[lan_route] search_lan_v6 WAN-hit tailcall to ifindex=%u",
                //            target->ifindex);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->ifindex);
                bpf_printk("[lan_route] search_lan_v6 WAN-hit tailcall FAILED ifindex=%u",
                           target->ifindex);
                return XDP_DROP;
            }
        }
    }

    key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (lan_cache) {
        struct rt_cache_value_v6 *target = bpf_map_lookup_elem(lan_cache, &search_key);
        if (target) {
            *flow_mark = target->mark_value;
            if (target->ifindex != 0) {
                if (target->is_docker) {
                    xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                    return XDP_PASS;
                }
                if (!target->xdp_redirect_able) {
                    int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex);
                    if (ret) return XDP_DROP;
                    return XDP_PASS;
                }
                if (target->has_mac) {
                    struct mac_key_v6 gw_key = {};
                    COPY_ADDR_FROM(gw_key.addr.bytes, target->gate_addr.bytes);
                    struct mac_value_v6 *mac_val = bpf_map_lookup_elem(&ip_mac_v6, &gw_key);
                    if (mac_val) {
                        void *data = (void *)(long)ctx->data;
                        void *data_end = (void *)(long)ctx->data_end;
                        struct ethhdr *eth = data;
                        if ((void *)(eth + 1) > data_end) return XDP_DROP;
                        __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
                        __builtin_memcpy(eth->h_source, target->mac, 6);
                    }
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->ifindex);
                bpf_printk("[lan_route] search_lan_v6 LAN-hit tailcall FAILED ifindex=%u",
                           target->ifindex);
                return XDP_DROP;
            }
            return xdp_cache_pick_wan_v6(ctx, context, target->mark_value);
        }
    }
    return 0;
}

// ── main XDP lan_route ──

SEC("xdp")
int xdp_lan_route(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    int ret;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == ETH_IPV4) {
        struct route_context_v4 context = {};
        ret = xdp_read_ipv4(ctx, &context);
        if (ret) return ret;

        ret = xdp_should_forward_v4(&context);
        if (ret) return ret;

        u32 flow_mark = 0;
        ret = xdp_search_route_in_lan_v4(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_lan_redirect_v4(ctx, &context);
        if (ret) return ret;

        ret = xdp_flow_verdict_v4(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_cache_pick_wan_v4(ctx, &context, flow_mark);
        if (ret) {
            return ret;
        }
        return XDP_DROP;
    } else if (eth->h_proto == ETH_IPV6) {
        struct route_context_v6 context = {};
        ret = xdp_read_ipv6(ctx, &context);
        if (ret) return ret;
        ret = xdp_should_forward_v6(&context);
        if (ret) return ret;

        u32 flow_mark = 0;
        ret = xdp_search_route_in_lan_v6(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_lan_redirect_v6(ctx, &context);
        if (ret) return ret;

        ret = xdp_flow_verdict_v6(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_cache_pick_wan_v6(ctx, &context, flow_mark);
        return ret ? ret : XDP_DROP;
    }

    return XDP_PASS;
}
