#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "base/landscape.h"

#include "chain/xdp_meta.h"
#include "chain/redirect_able.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

#include "route/route4_context.h"
#include "route/route6_context.h"
#include "route/flow4_maps.h"
#include "route/route4_cache.h"
#include "route/route4_lan.h"
#include "route/route4_slot.h"
#include "route/flow6_maps.h"
#include "route/route6_cache.h"
#include "route/route6_lan.h"
#include "route/route6_slot.h"
#include "route/xdp_route_read.h"

#include "route/flow_match.h"
#include "neigh/neigh_ip4.h"
#include "neigh/neigh_ip6.h"
#include "route/neigh_learn.h"

char LICENSE[] SEC("license") = "GPL";

// ── XDP flow_id matching (MAC at eth->h_source, no current_l3_offset check needed) ──

static __always_inline int xdp_match_flow_id_v4(struct xdp_md *ctx, __be32 saddr,
                                                u32 *default_flow_id_) {
    struct flow_match_key match_key = {};
    u32 ret_flow_id = *default_flow_id_;

    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);
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
    match_key.src_addr.in6_u.u6_addr32[0] = saddr;

    flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    *default_flow_id_ = ret_flow_id;
    return 0;
}

static __always_inline int xdp_match_flow_id_v6(struct xdp_md *ctx, const struct in6_addr *saddr,
                                                u32 *default_flow_id_) {
    struct flow_match_key match_key = {};
    u32 ret_flow_id = *default_flow_id_;

    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);
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
    COPY_ADDR_FROM(match_key.src_addr.in6_u.u6_addr32, saddr->in6_u.u6_addr8);

    flow_id_ptr = bpf_map_lookup_elem(&flow_match_map, &match_key);
    if (flow_id_ptr != NULL) {
        ret_flow_id = *flow_id_ptr;
    }

    *default_flow_id_ = ret_flow_id;
    return 0;
}

// ── XDP-adapted flow_verdict ──

static __always_inline int
xdp_route4_flow_verdict(struct xdp_md *ctx, struct route4_context *context, u32 *init_flow_id_) {
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (xdp_match_flow_id_v4(ctx, context->saddr, (u32 *)&flow_id)) {
        return XDP_DROP;
    }
    const u32 src_flow_id = flow_id;

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

    if (unlikely(flow_has_l4_rules(src_flow_id))) {
        const struct flow_l4_rule_set *l4_set =
            bpf_map_lookup_elem(&flow_l4_rule_map, &src_flow_id);
        u16 best_prio = priority;
        if (l4_set != NULL && l4_set->count > 0 && best_prio >= l4_set->entries[0].priority) {
            context->skip_2tuple_cache = 1;
            route4_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
            if (context->has_ports) {
                u16 host_dport = bpf_ntohs(context->dport);
                u32 cnt = l4_set->count;
                if (cnt > FLOW_L4_MAX_RULES_PER_FLOW) cnt = FLOW_L4_MAX_RULES_PER_FLOW;
                for (u32 i = 0; i < FLOW_L4_MAX_RULES_PER_FLOW; i++) {
                    if (i >= cnt) break;
                    const struct flow_l4_rule_entry *e = &l4_set->entries[i];
                    if (e->priority > best_prio) break;
                    if ((e->l4_proto == 0 || e->l4_proto == context->l4_protocol) &&
                        host_dport >= e->start_port && host_dport <= e->end_port) {
                        flow_mark_action = e->mark;
                        priority = e->priority;
                        break;
                    }
                }
            }
        }
    }

    flow_action = get_flow_action(flow_mark_action);
    if (flow_action == FLOW_KEEP_GOING) {
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        if (unlikely(context->skip_2tuple_cache && context->has_ports)) {
            u32 l4_slot = L4_VERDICT_CACHE;
            void *conn_inner = bpf_map_lookup_elem(&rt4_conn_map, &l4_slot);
            if (conn_inner != NULL) {
                struct route4_conn_key conn_key = {
                    .saddr = context->saddr,
                    .daddr = context->daddr,
                    .sport = context->sport,
                    .dport = context->dport,
                    .l4_proto = context->l4_protocol,
                };
                struct route_conn_value drop_conn = {
                    .mark_value = flow_mark_action,
                    .flags = ROUTE_CONN_FLAG_DROP,
                };
                bpf_map_update_elem(conn_inner, &conn_key, &drop_conn, BPF_ANY);
            }
        }
        return XDP_DROP;
    }

keep_going:
    *init_flow_id_ = flow_mark_action;
    return 0;
}

static __always_inline int
xdp_route6_flow_verdict(struct xdp_md *ctx, struct route6_context *context, u32 *init_flow_id_) {
    volatile u32 flow_id = *init_flow_id_ & 0xff;
    u8 flow_action;

    if (xdp_match_flow_id_v6(ctx, &context->saddr, (u32 *)&flow_id)) {
        return XDP_DROP;
    }
    const u32 src_flow_id = flow_id;

    volatile u32 flow_mark_action = *init_flow_id_;
    volatile u16 priority = 0xFFFF;

    struct flow_ip_trie_key_v6 ip_trie_key = {.prefixlen = 128};
    COPY_ADDR_FROM(ip_trie_key.addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8);
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

    if (unlikely(flow_has_l4_rules(src_flow_id))) {
        const struct flow_l4_rule_set *l4_set =
            bpf_map_lookup_elem(&flow_l4_rule_map, &src_flow_id);
        u16 best_prio = priority;
        if (l4_set != NULL && l4_set->count > 0 && best_prio >= l4_set->entries[0].priority) {
            context->skip_2tuple_cache = 1;
            route6_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
            if (context->has_ports) {
                u16 host_dport = bpf_ntohs(context->dport);
                u32 cnt = l4_set->count;
                if (cnt > FLOW_L4_MAX_RULES_PER_FLOW) cnt = FLOW_L4_MAX_RULES_PER_FLOW;
                for (u32 i = 0; i < FLOW_L4_MAX_RULES_PER_FLOW; i++) {
                    if (i >= cnt) break;
                    const struct flow_l4_rule_entry *e = &l4_set->entries[i];
                    if (e->priority > best_prio) break;
                    if ((e->l4_proto == 0 || e->l4_proto == context->l4_protocol) &&
                        host_dport >= e->start_port && host_dport <= e->end_port) {
                        flow_mark_action = e->mark;
                        priority = e->priority;
                        break;
                    }
                }
            }
        }
    }

    flow_action = get_flow_action(flow_mark_action);
    if (flow_action == FLOW_KEEP_GOING) {
        flow_mark_action = replace_flow_id(flow_mark_action, flow_id & 0xFF);
    } else if (flow_action == FLOW_DIRECT) {
        flow_mark_action = replace_flow_id(flow_mark_action, 0);
        goto keep_going;
    } else if (flow_action == FLOW_DROP) {
        if (unlikely(context->skip_2tuple_cache && context->has_ports)) {
            u32 l4_slot = L4_VERDICT_CACHE;
            void *conn_inner = bpf_map_lookup_elem(&rt6_conn_map, &l4_slot);
            if (conn_inner != NULL) {
                struct route6_conn_key conn_key = {
                    .saddr = context->saddr,
                    .daddr = context->daddr,
                    .sport = context->sport,
                    .dport = context->dport,
                    .l4_proto = context->l4_protocol,
                };
                struct route_conn_value drop_conn = {
                    .mark_value = flow_mark_action,
                    .flags = ROUTE_CONN_FLAG_DROP,
                };
                bpf_map_update_elem(conn_inner, &conn_key, &drop_conn, BPF_ANY);
            }
        }
        return XDP_DROP;
    }

keep_going:
    *init_flow_id_ = flow_mark_action;
    return 0;
}

// ── XDP cache-pick-wan: pickup + write cache ──

static __always_inline struct route4_target_info *
xdp_route4_pick_wan_target(struct xdp_md *ctx, struct route4_context *context, u32 flow_mark) {
    const u32 resolved_flow_id = get_flow_id(flow_mark);

    if (likely(!route_flow_is_five_tuple(resolved_flow_id))) {
        struct route4_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route4_target_slot(context->daddr),
        };
        return bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
    }

    route4_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
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
                    if (conn_val->mark_value != flow_mark || conn_val->has_mac != pinned->has_mac ||
                        conn_val->is_docker != pinned->is_docker ||
                        conn_val->xdp_redirect_able != xdp_able || conn_val->flags != 0 ||
                        conn_val->link_chain_id != pinned->link_chain_id) {
                        struct route_conn_value refreshed = {
                            .mark_value = flow_mark,
                            .has_mac = pinned->has_mac,
                            .is_docker = pinned->is_docker,
                            .xdp_redirect_able = xdp_able,
                            .flags = 0,
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
        struct route4_target_info *info = bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
        if (info != NULL && info->ifindex != 0 && conn_inner != NULL) {
            struct route_conn_value new_conn = {
                .mark_value = flow_mark,
                .has_mac = info->has_mac,
                .is_docker = info->is_docker,
                .xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0,
                .flags = 0,
                .ifindex = info->ifindex,
                .link_chain_id = info->link_chain_id,
                ._pad = 0,
            };
            bpf_map_update_elem(conn_inner, &conn_key, &new_conn, BPF_ANY);
        }
        return info;
    }

    struct route4_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route4_target_slot(context->daddr),
    };
    return bpf_map_lookup_elem(&rt4_slot_map, &slot_key);
}

static __always_inline int xdp_route_send_lan_cached(struct xdp_md *ctx, u32 mark_value,
                                                     u32 target_ifindex, u16 link_chain_id,
                                                     u8 is_docker, u8 cached_xdp_able) {
    if (is_docker) {
        xdp_set_docker_meta(ctx, mark_value, target_ifindex);
        return XDP_PASS;
    }
    if (!cached_xdp_able || !xdp_redirect_target_able(target_ifindex)) {
        int ret = xdp_set_tc_redirect_meta(ctx, mark_value, target_ifindex, link_chain_id);
        if (ret) return XDP_DROP;
        return XDP_PASS;
    }

    struct xdp_pipe_meta orig_meta = {};
    bool had_meta = (xdp_get_meta(ctx, &orig_meta) == 0);
    struct xdp_pipe_meta meta = orig_meta;
    meta.target_ifindex = target_ifindex;
    meta.mark = mark_value;
    if (xdp_set_meta(ctx, &meta) == 0) {
        bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, link_chain_id);
        bpf_xdp_adjust_meta(ctx, (int)sizeof(meta));
        if (had_meta) {
            void *data_meta = ctx_data_meta(ctx);
            void *data = ctx_data(ctx);
            if (data_meta + sizeof(orig_meta) <= data) {
                __builtin_memcpy(data_meta, &orig_meta, sizeof(orig_meta));
            }
        }
    }
    bpf_printk("[lan_route] outbound tailcall FAILED chain=%u, fallback XDP_PASS", link_chain_id);
    return XDP_PASS;
}

static __always_inline int xdp_route4_send_to_target(struct xdp_md *ctx,
                                                     const struct route4_target_info *info,
                                                     const u32 flow_id) {
    if (info->ifindex == ctx->ingress_ifindex) return 0;
    return xdp_route_send_lan_cached(ctx, flow_id, info->ifindex, info->link_chain_id,
                                     info->is_docker, 1);
}

static __always_inline int xdp_route_send_by_conn_value(struct xdp_md *ctx,
                                                        const struct route_conn_value *target) {
    if (target->ifindex == ctx->ingress_ifindex) return 0;
    return xdp_route_send_lan_cached(ctx, target->mark_value, target->ifindex,
                                     target->link_chain_id, target->is_docker,
                                     target->xdp_redirect_able);
}

static __always_inline int
xdp_route4_cache_pick_wan(struct xdp_md *ctx, struct route4_context *context, const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);
    struct route4_target_info *info = xdp_route4_pick_wan_target(ctx, context, flow_id);
    if (info == NULL || info->ifindex == 0) {
        if (resolved_flow_id == 0) return 0;
        return XDP_DROP;
    }

    if (info->ifindex == ctx->ingress_ifindex) return 0;

    const bool is_five_tuple = route_flow_is_five_tuple(resolved_flow_id);
    if (!is_five_tuple) {
        bool already_cached = false;
        struct route4_cache_key cache_key = {.local_addr = context->saddr,
                                             .remote_addr = context->daddr};

        u32 wan_key = WAN_CACHE;
        void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &wan_key);
        if (wan_cache) {
            if (bpf_map_lookup_elem(wan_cache, &cache_key) != NULL) already_cached = true;
        }

        if (!already_cached) {
            if (unlikely(context->skip_2tuple_cache)) {
                if (context->has_ports) {
                    u32 l4_slot = L4_VERDICT_CACHE;
                    void *conn_inner = bpf_map_lookup_elem(&rt4_conn_map, &l4_slot);
                    if (conn_inner != NULL) {
                        struct route4_conn_key conn_key = {
                            .saddr = context->saddr,
                            .daddr = context->daddr,
                            .sport = context->sport,
                            .dport = context->dport,
                            .l4_proto = context->l4_protocol,
                        };
                        struct route_conn_value new_conn = {
                            .mark_value = flow_id,
                            .has_mac = info->has_mac,
                            .is_docker = info->is_docker,
                            .xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0,
                            .flags = 0,
                            .ifindex = info->ifindex,
                            .link_chain_id = info->link_chain_id,
                            ._pad = 0,
                        };
                        bpf_map_update_elem(conn_inner, &conn_key, &new_conn, BPF_ANY);
                    }
                }
            } else {
                u32 lan_key = LAN_CACHE;
                void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &lan_key);
                if (lan_cache) {
                    struct route4_cache_value new_entry = {};
                    new_entry.mark_value = flow_id;
                    new_entry.ifindex = info->ifindex;
                    new_entry.has_mac = info->has_mac;
                    new_entry.is_docker = info->is_docker;
                    new_entry.xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                    new_entry.link_chain_id = info->link_chain_id;
                    bpf_map_update_elem(lan_cache, &cache_key, &new_entry, BPF_ANY);
                }
            }
        }
    }

    return xdp_route4_send_to_target(ctx, info, flow_id);
}

static __always_inline struct route6_target_info *
xdp_route6_pick_wan_target(struct xdp_md *ctx, struct route6_context *context, u32 flow_mark) {
    const u32 resolved_flow_id = get_flow_id(flow_mark);

    if (likely(!route_flow_is_five_tuple(resolved_flow_id))) {
        struct route6_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route6_target_slot(&context->daddr),
        };
        return bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
    }

    route6_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
    if (context->has_ports) {
        struct route6_conn_key conn_key = {
            .saddr = context->saddr,
            .daddr = context->daddr,
            .sport = context->sport,
            .dport = context->dport,
            .l4_proto = context->l4_protocol,
        };
        u32 conn_slot = CONN_PIN_CACHE;
        void *conn_inner = bpf_map_lookup_elem(&rt6_conn_map, &conn_slot);
        if (conn_inner != NULL) {
            struct route_conn_value *conn_val = bpf_map_lookup_elem(conn_inner, &conn_key);
            if (conn_val != NULL && conn_val->ifindex != 0) {
                struct route_flow_target_key ft_key = {
                    .flow_id = resolved_flow_id,
                    .ifindex = conn_val->ifindex,
                };
                struct route6_target_info *pinned = bpf_map_lookup_elem(&rt6_flow_targets, &ft_key);
                if (pinned != NULL && pinned->ifindex != 0) {
                    u8 xdp_able = xdp_redirect_target_able(pinned->ifindex) ? 1 : 0;
                    if (conn_val->mark_value != flow_mark || conn_val->has_mac != pinned->has_mac ||
                        conn_val->is_docker != pinned->is_docker ||
                        conn_val->xdp_redirect_able != xdp_able || conn_val->flags != 0 ||
                        conn_val->link_chain_id != pinned->link_chain_id) {
                        struct route_conn_value refreshed = {
                            .mark_value = flow_mark,
                            .has_mac = pinned->has_mac,
                            .is_docker = pinned->is_docker,
                            .xdp_redirect_able = xdp_able,
                            .flags = 0,
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

        struct route6_slot_key slot_key = {
            .flow_id = resolved_flow_id,
            .slot = route6_five_tuple_slot(&context->saddr, &context->daddr, context->sport,
                                           context->dport, context->l4_protocol),
        };
        struct route6_target_info *info = bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
        if (info != NULL && info->ifindex != 0 && conn_inner != NULL) {
            struct route_conn_value new_conn = {
                .mark_value = flow_mark,
                .has_mac = info->has_mac,
                .is_docker = info->is_docker,
                .xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0,
                .flags = 0,
                .ifindex = info->ifindex,
                .link_chain_id = info->link_chain_id,
                ._pad = 0,
            };
            bpf_map_update_elem(conn_inner, &conn_key, &new_conn, BPF_ANY);
        }
        return info;
    }

    struct route6_slot_key slot_key = {
        .flow_id = resolved_flow_id,
        .slot = route6_target_slot(&context->daddr),
    };
    return bpf_map_lookup_elem(&rt6_slot_map, &slot_key);
}

static __always_inline int xdp_route6_send_to_target(struct xdp_md *ctx,
                                                     const struct route6_target_info *info,
                                                     const u32 flow_id) {
    if (info->ifindex == ctx->ingress_ifindex) {
        return 0;
    }
    return xdp_route_send_lan_cached(ctx, flow_id, info->ifindex, info->link_chain_id,
                                     info->is_docker, 1);
}

static __always_inline int
xdp_route6_cache_pick_wan(struct xdp_md *ctx, struct route6_context *context, const u32 flow_id) {
    const u32 resolved_flow_id = get_flow_id(flow_id);
    struct route6_target_info *info = xdp_route6_pick_wan_target(ctx, context, flow_id);
    if (info == NULL || info->ifindex == 0) {
        if (resolved_flow_id == 0) {
            return 0;
        }
        return XDP_DROP;
    }

    if (info->ifindex == ctx->ingress_ifindex) {
        return 0;
    }

    const bool is_five_tuple = route_flow_is_five_tuple(resolved_flow_id);
    if (!is_five_tuple) {
        bool already_cached = false;
        struct route6_cache_key cache_key = {};
        __builtin_memcpy(cache_key.local_addr.in6_u.u6_addr8, context->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(cache_key.remote_addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8, 16);

        u32 wan_key = WAN_CACHE;
        void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &wan_key);
        if (wan_cache) {
            if (bpf_map_lookup_elem(wan_cache, &cache_key) != NULL) already_cached = true;
        }

        if (!already_cached) {
            if (unlikely(context->skip_2tuple_cache)) {
                if (context->has_ports) {
                    u32 l4_slot = L4_VERDICT_CACHE;
                    void *conn_inner = bpf_map_lookup_elem(&rt6_conn_map, &l4_slot);
                    if (conn_inner != NULL) {
                        struct route6_conn_key conn_key = {
                            .saddr = context->saddr,
                            .daddr = context->daddr,
                            .sport = context->sport,
                            .dport = context->dport,
                            .l4_proto = context->l4_protocol,
                        };
                        struct route_conn_value new_conn = {
                            .mark_value = flow_id,
                            .has_mac = info->has_mac,
                            .is_docker = info->is_docker,
                            .xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0,
                            .flags = 0,
                            .ifindex = info->ifindex,
                            .link_chain_id = info->link_chain_id,
                            ._pad = 0,
                        };
                        bpf_map_update_elem(conn_inner, &conn_key, &new_conn, BPF_ANY);
                    }
                }
            } else {
                u32 lan_key = LAN_CACHE;
                void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &lan_key);
                if (lan_cache) {
                    struct route6_cache_value new_entry = {};
                    new_entry.mark_value = flow_id;
                    new_entry.ifindex = info->ifindex;
                    new_entry.has_mac = info->has_mac;
                    new_entry.is_docker = info->is_docker;
                    new_entry.xdp_redirect_able = xdp_redirect_target_able(info->ifindex) ? 1 : 0;
                    new_entry.link_chain_id = info->link_chain_id;
                    bpf_map_update_elem(lan_cache, &cache_key, &new_entry, BPF_ANY);
                }
            }
        }
    }

    return xdp_route6_send_to_target(ctx, info, flow_id);
}

// ── LAN→LAN redirect (shared with xdp_wan_route) ──

static __always_inline int xdp_route4_lan_redirect_check_in_lan(struct xdp_md *ctx,
                                                                struct route4_context *context) {
    struct route4_lan_key key = {.prefixlen = 32, .addr = context->daddr};
    struct mac_key_v4 mac_key = {.addr = context->daddr};
    struct mac_value_v4 *mac_val;
    int ret;

    struct route4_lan_info *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &key);
    if (lan_info == NULL) return 0;

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        if (lan_info->addr == context->daddr) return XDP_PASS;
        return 0;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) return XDP_PASS;
    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) return XDP_PASS;

    if (lan_info->has_mac) {
        mac_key.addr = lan_info->route_type == ROUTE_TYPE_NEXTHOP ? lan_info->addr : context->daddr;
        mac_val = bpf_map_lookup_elem(&ip_mac_v4, &mac_key);
        if (mac_val) {
            void *data = ctx_data(ctx);
            void *data_end = ctx_data_end(ctx);
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            ret = xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
            // ld_from_lan_log("bpf_redirect 1 %pI4 -> %pI4 idx: %d ret: %d", &context->saddr,
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

            void *data = ctx_data(ctx);
            void *data_end = ctx_data_end(ctx);
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, fib.dmac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            // ld_from_lan_log("bpf_redirect 2");
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
        }
        return 0;
    }

    // ld_from_lan_log("bpf_redirect 3");
    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
}

static __always_inline int xdp_route6_lan_redirect_check_in_lan(struct xdp_md *ctx,
                                                                struct route6_context *context) {
    struct route6_lan_key key = {.prefixlen = 128};
    struct mac_value_v6 *mac_val;
    COPY_ADDR_FROM(key.addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8);

    struct route6_lan_info *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &key);
    if (lan_info == NULL) return 0;

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        if (ip_addr_equal_in6(&lan_info->addr, &context->daddr)) return XDP_PASS;
        return 0;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) return XDP_PASS;
    if (lan_info->route_type == ROUTE_TYPE_LAN &&
        ip_addr_equal_in6(&lan_info->addr, &context->daddr))
        return XDP_PASS;

    if (lan_info->has_mac) {
        struct mac_key_v6 hop_key = {};
        COPY_ADDR_FROM(hop_key.addr.in6_u.u6_addr32, lan_info->route_type == ROUTE_TYPE_NEXTHOP
                                                         ? lan_info->addr.in6_u.u6_addr32
                                                         : context->daddr.in6_u.u6_addr32);
        mac_val = bpf_map_lookup_elem(&ip_mac_v6, &hop_key);
        if (mac_val) {
            void *data = ctx_data(ctx);
            void *data_end = ctx_data_end(ctx);
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
        }

        struct bpf_fib_lookup fib = {};
        fib.family = AF_INET6;
        fib.tot_len = sizeof(struct ipv6hdr);
        COPY_ADDR_FROM(fib.ipv6_src, context->saddr.in6_u.u6_addr32);
        COPY_ADDR_FROM(fib.ipv6_dst, hop_key.addr.in6_u.u6_addr32);
        fib.ifindex = ctx->ingress_ifindex;

        int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
            if (fib.ifindex == ctx->ingress_ifindex) return XDP_PASS;

            struct mac_value_v6 new_val = {.ifindex = lan_info->ifindex, .proto = ETH_IPV6};
            __builtin_memcpy(new_val.mac, fib.dmac, 6);
            __builtin_memcpy(new_val.dev_mac, lan_info->mac_addr, 6);
            bpf_map_update_elem(&ip_mac_v6, &hop_key, &new_val, BPF_ANY);

            void *data = ctx_data(ctx);
            void *data_end = ctx_data_end(ctx);
            struct ethhdr *eth = data;
            if ((void *)(eth + 1) > data_end) return XDP_PASS;
            __builtin_memcpy(eth->h_dest, fib.dmac, 6);
            __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
            return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
        }
        return 0;
    }

    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, 0, 0);
}

// ── search_cache_in_lan: cache lookup → tailcall to LAN→WAN chain ──

static __always_inline int xdp_route4_search_cache_in_lan(struct xdp_md *ctx,
                                                          struct route4_context *context) {
    {
        struct route4_cache_key search_key = {.local_addr = context->saddr,
                                              .remote_addr = context->daddr};
        u32 key = WAN_CACHE;
        void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
        if (wan_cache) {
            struct route4_cache_value *target = bpf_map_lookup_elem(wan_cache, &search_key);
            if (target) {
                if (!target->ifindex) return XDP_DROP;
                // bpf_printk("[wan_cache_r] v4 HIT src=%pI4 dst=%pI4 ifindex=%u has_mac=%u",
                //            &context->saddr, &context->daddr, target->ifindex, target->has_mac);
                if (target->is_docker) {
                    xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                    return XDP_PASS;
                }
                if (!target->xdp_redirect_able) {
                    int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex,
                                                       target->link_chain_id);
                    if (ret) return XDP_DROP;
                    return XDP_PASS;
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                // bpf_printk("[lan_route] search_lan_v4 WAN-hit tailcall to chain=%u",
                //            target->link_chain_id);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->link_chain_id);
                bpf_printk("[lan_route] search_lan_v4 WAN-hit tailcall FAILED chain=%u",
                           target->link_chain_id);
                // WAN_CACHE pins return traffic to the original WAN link; drop when
                // its chain is unavailable rather than rerouting to another WAN.
                return XDP_DROP;
            }
        }

        key = LAN_CACHE;
        void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
        if (lan_cache) {
            struct route4_cache_value *target = bpf_map_lookup_elem(lan_cache, &search_key);
            if (target && target->ifindex != 0) {
                // As on a slot hit, the selected WAN root owns the Ethernet header.
                return xdp_route_send_lan_cached(ctx, target->mark_value, target->ifindex,
                                                 target->link_chain_id, target->is_docker,
                                                 target->xdp_redirect_able);
            }
        }
    }
    const bool check_five_tuple = route_any_flow_is_five_tuple();
    const bool check_l4 = any_flow_has_l4_rules();
    if (unlikely(check_five_tuple || check_l4)) {
        route4_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
        if (context->has_ports) {
            struct route4_conn_key conn_key = {
                .saddr = context->saddr,
                .daddr = context->daddr,
                .sport = context->sport,
                .dport = context->dport,
                .l4_proto = context->l4_protocol,
            };
            struct route_conn_value *conn_val = NULL;
            if (check_five_tuple) {
                u32 conn_slot = CONN_PIN_CACHE;
                void *conn_inner = bpf_map_lookup_elem(&rt4_conn_map, &conn_slot);
                if (conn_inner != NULL) {
                    conn_val = bpf_map_lookup_elem(conn_inner, &conn_key);
                }
            }
            if (conn_val == NULL && check_l4) {
                u32 l4_slot = L4_VERDICT_CACHE;
                void *l4_inner = bpf_map_lookup_elem(&rt4_conn_map, &l4_slot);
                if (l4_inner != NULL) {
                    conn_val = bpf_map_lookup_elem(l4_inner, &conn_key);
                }
            }
            if (conn_val != NULL) {
                if (unlikely(conn_val->flags & ROUTE_CONN_FLAG_DROP)) {
                    return XDP_DROP;
                }
                if (conn_val->ifindex != 0) {
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
                        return xdp_route_send_by_conn_value(ctx, conn_val);
                    }
                }
            }
        }
    }

    return 0;
}

static __always_inline int xdp_route6_search_cache_in_lan(struct xdp_md *ctx,
                                                          struct route6_context *context) {
    {
        struct route6_cache_key search_key = {};
        __builtin_memcpy(search_key.local_addr.in6_u.u6_addr8, context->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(search_key.remote_addr.in6_u.u6_addr8, context->daddr.in6_u.u6_addr8, 16);

        u32 key = WAN_CACHE;
        void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
        if (wan_cache) {
            struct route6_cache_value *target = bpf_map_lookup_elem(wan_cache, &search_key);
            if (target) {
                if (!target->ifindex) return XDP_DROP;
                if (target->is_docker) {
                    xdp_set_docker_meta(ctx, target->mark_value, target->ifindex);
                    return XDP_PASS;
                }
                // bpf_printk("[wan_cache_r] v6 HIT src=%pI6c dst=%pI6c ifindex=%u has_mac=%u",
                //            &context->saddr, &context->daddr, target->ifindex, target->has_mac);
                if (!target->xdp_redirect_able) {
                    int ret = xdp_set_tc_redirect_meta(ctx, target->mark_value, target->ifindex,
                                                       target->link_chain_id);
                    if (ret) return XDP_DROP;
                    return XDP_PASS;
                }
                struct xdp_pipe_meta meta = {};
                xdp_get_meta(ctx, &meta);
                meta.target_ifindex = target->ifindex;
                meta.mark = target->mark_value;
                xdp_set_meta(ctx, &meta);
                bpf_tail_call(ctx, &xdp_lan_pipe_root_progs, target->link_chain_id);
                bpf_printk("[lan_route] search_lan_v6 WAN-hit tailcall FAILED chain=%u",
                           target->link_chain_id);
                // See the v4 path: WAN_CACHE pins return traffic to the original
                // WAN link and drops when its chain is unavailable.
                return XDP_DROP;
            }
        }

        key = LAN_CACHE;
        void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
        if (lan_cache) {
            struct route6_cache_value *target = bpf_map_lookup_elem(lan_cache, &search_key);
            if (target && target->ifindex != 0) {
                // As on a slot hit, the selected WAN root owns the Ethernet header.
                return xdp_route_send_lan_cached(ctx, target->mark_value, target->ifindex,
                                                 target->link_chain_id, target->is_docker,
                                                 target->xdp_redirect_able);
            }
        }
    }

    const bool check_five_tuple = route_any_flow_is_five_tuple();
    const bool check_l4 = any_flow_has_l4_rules();
    if (unlikely(check_five_tuple || check_l4)) {
        route6_ensure_l4_ports_xdp(ctx, sizeof(struct ethhdr), context);
        if (context->has_ports) {
            struct route6_conn_key conn_key = {
                .saddr = context->saddr,
                .daddr = context->daddr,
                .sport = context->sport,
                .dport = context->dport,
                .l4_proto = context->l4_protocol,
            };
            struct route_conn_value *conn_val = NULL;
            if (check_five_tuple) {
                u32 conn_slot = CONN_PIN_CACHE;
                void *conn_inner = bpf_map_lookup_elem(&rt6_conn_map, &conn_slot);
                if (conn_inner != NULL) {
                    conn_val = bpf_map_lookup_elem(conn_inner, &conn_key);
                }
            }
            if (conn_val == NULL && check_l4) {
                u32 l4_slot = L4_VERDICT_CACHE;
                void *l4_inner = bpf_map_lookup_elem(&rt6_conn_map, &l4_slot);
                if (l4_inner != NULL) {
                    conn_val = bpf_map_lookup_elem(l4_inner, &conn_key);
                }
            }
            if (conn_val != NULL) {
                if (unlikely(conn_val->flags & ROUTE_CONN_FLAG_DROP)) {
                    return XDP_DROP;
                }
                if (conn_val->ifindex != 0) {
                    struct route_flow_target_key ft_key = {
                        .flow_id = get_flow_id(conn_val->mark_value),
                        .ifindex = conn_val->ifindex,
                    };
                    struct route6_target_info *live =
                        bpf_map_lookup_elem(&rt6_flow_targets, &ft_key);
                    if (live != NULL && live->ifindex != 0 &&
                        live->link_chain_id == conn_val->link_chain_id &&
                        live->has_mac == conn_val->has_mac &&
                        live->is_docker == conn_val->is_docker) {
                        return xdp_route_send_by_conn_value(ctx, conn_val);
                    }
                }
            }
        }
    }

    return 0;
}

// ── main XDP lan route ──

SEC("xdp")
int xdp_lan_route(struct xdp_md *ctx) {
    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);
    struct ethhdr *eth = data;
    int ret;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (unlikely(is_broadcast_or_mcast_mac(eth->h_dest))) return XDP_PASS;

    if (eth->h_proto == ETH_IPV4) {
        struct route4_context context = {};
        ret = xdp_read_ipv4(ctx, &context);
        if (ret) return ret;

        if (unlikely(is_broadcast_ip4(context.daddr))) {
            return XDP_PASS;
        }

        ret = xdp_route4_search_cache_in_lan(ctx, &context);
        if (ret) return ret;

        learn_src_ip_mac_v4_xdp(ctx, &context);

        ret = xdp_route4_lan_redirect_check_in_lan(ctx, &context);
        if (ret) return ret;

        u32 flow_mark = 0;
        ret = xdp_route4_flow_verdict(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_route4_cache_pick_wan(ctx, &context, flow_mark);
        if (ret) {
            return ret;
        }
        return XDP_DROP;
    } else if (eth->h_proto == ETH_IPV6) {
        struct route6_context context = {};
        ret = xdp_read_ipv6(ctx, &context);
        if (ret) return ret;

        if (unlikely(is_broadcast_ip6(context.daddr.in6_u.u6_addr8))) {
            return XDP_PASS;
        }

        ret = xdp_route6_search_cache_in_lan(ctx, &context);
        if (ret) return ret;

        learn_src_ip_mac_v6_xdp(ctx, &context);

        ret = xdp_route6_lan_redirect_check_in_lan(ctx, &context);
        if (ret) return ret;

        u32 flow_mark = 0;
        ret = xdp_route6_flow_verdict(ctx, &context, &flow_mark);
        if (ret) return ret;

        ret = xdp_route6_cache_pick_wan(ctx, &context, flow_mark);
        return ret ? ret : XDP_DROP;
    }

    return XDP_PASS;
}
