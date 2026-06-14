#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "landscape.h"
#include "land_wan_ip.h"
#include "base/dummy.h"

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

// ── XDP-native packet reading (replaces scan_route_packet + read_route_context) ──

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

// ── Forwarding checks (unchanged logic) ──

static __always_inline int xdp_should_forward_v4(const struct route_context_v4 *context) {
    return should_not_forward(context->daddr) ? XDP_DROP : 0;
}

static __always_inline int xdp_should_forward_v6(const struct route_context_v6 *context) {
    return is_broadcast_ip6(context->daddr.bytes) == TC_ACT_UNSPEC ? XDP_DROP : 0;
}

// ── is_current_wan_packet: skb->ingress_ifindex → ctx->ingress_ifindex ──

static __always_inline int xdp_is_wan_packet_v4(struct xdp_md *ctx,
                                                struct route_context_v4 *context) {
    struct wan_ip_info_key key = {};
    key.ifindex = ctx->ingress_ifindex;
    key.l3_protocol = LANDSCAPE_IPV4_TYPE;

    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &key);
    if (wan_info != NULL && wan_info->addr.ip == context->daddr) return XDP_PASS;
    return 0;
}

static __always_inline int xdp_is_wan_packet_v6(struct xdp_md *ctx,
                                                struct route_context_v6 *context) {
    struct wan_ip_info_key key = {};
    key.ifindex = ctx->ingress_ifindex;
    key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &key);
    if (wan_info != NULL && ip_addr_equal_x(&wan_info->addr, &context->daddr)) return XDP_PASS;
    return 0;
}

// ── lan_redirect: lan_map lookup with MAC resolution via cache or FIB ──

static __always_inline int xdp_lan_redirect_v4(struct xdp_md *ctx, struct route_context_v4 *context,
                                               struct xdp_pipe_meta *meta) {
#define BPF_LOG_TOPIC "xdp_lan_redirect_v4"
    struct lan_route_key_v4 lan_key = {.prefixlen = 32, .addr = context->daddr};
    struct mac_key_v4 mac_key = {.addr = context->daddr};
    struct mac_value_v4 *mac_val;

    // ① lan_map lookup (existing user-configured routes)
    struct lan_route_info_v4 *lan_info = bpf_map_lookup_elem(&rt4_lan_map, &lan_key);
    if (lan_info == NULL) {
        return XDP_ABORTED;
    }

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        return XDP_PASS;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) {
        return XDP_PASS;
    }
    if (lan_info->route_type == ROUTE_TYPE_LAN && lan_info->addr == context->daddr) {
        return XDP_PASS;
    }

    if (!lan_info->has_mac) {
        return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
    }

    mac_key.addr = lan_info->route_type == ROUTE_TYPE_NEXTHOP ? lan_info->addr : context->daddr;
    mac_val = bpf_map_lookup_elem(&ip_mac_v4, &mac_key);
    if (mac_val) {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        __builtin_memcpy(eth->h_dest, mac_val->mac, 6);
        __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
        return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
    }

    // fib_lookup to fill MAC when neighbor cache missed
    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET;
    fib.tot_len = sizeof(struct iphdr);
    fib.ipv4_src = context->saddr;
    fib.ipv4_dst = context->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        if (fib.ifindex == ctx->ingress_ifindex) return XDP_PASS;

        struct mac_value_v4 new_val = {};
        new_val.ifindex = fib.ifindex;
        new_val.proto = ETH_IPV4;
        __builtin_memcpy(new_val.mac, fib.dmac, 6);
        __builtin_memcpy(new_val.dev_mac, fib.smac, 6);
        bpf_map_update_elem(&ip_mac_v4, &mac_key, &new_val, BPF_ANY);

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        __builtin_memcpy(eth->h_dest, fib.dmac, 6);
        __builtin_memcpy(eth->h_source, fib.smac, 6);
        return xdp_redirect_or_tc_handoff(ctx, fib.ifindex, meta->mark);
    }

    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
#undef BPF_LOG_TOPIC
}

static __always_inline int xdp_lan_redirect_v6(struct xdp_md *ctx, struct route_context_v6 *context,
                                               struct xdp_pipe_meta *meta) {
    struct lan_route_key_v6 lan_key = {.prefixlen = 128};
    struct mac_key_v6 mac_key = {};
    struct mac_value_v6 *mac_val;
    COPY_ADDR_FROM(lan_key.addr.bytes, context->daddr.bytes);
    COPY_ADDR_FROM(mac_key.addr.bytes, context->daddr.bytes);

    // ① lan_map lookup
    struct lan_route_info_v6 *lan_info = bpf_map_lookup_elem(&rt6_lan_map, &lan_key);
    if (lan_info == NULL) {
        return XDP_ABORTED;
    }

    if (lan_info->route_type == ROUTE_TYPE_WAN) {
        return XDP_PASS;
    }

    if (lan_info->ifindex == ctx->ingress_ifindex) {
        return XDP_PASS;
    }
    if (lan_info->route_type == ROUTE_TYPE_LAN &&
        ip_addr_equal_in6(&lan_info->addr, &context->daddr)) {
        return XDP_PASS;
    }

    if (!lan_info->has_mac) {
        return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
    }

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
        return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
    }

    // fib_lookup to fill MAC when neighbor cache missed
    struct bpf_fib_lookup fib = {};
    fib.family = AF_INET6;
    COPY_ADDR_FROM(fib.ipv6_src, context->saddr.all);
    COPY_ADDR_FROM(fib.ipv6_dst, context->daddr.all);
    fib.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        if (fib.ifindex == ctx->ingress_ifindex) return XDP_PASS;

        struct mac_value_v6 new_val = {};
        new_val.ifindex = fib.ifindex;
        new_val.proto = ETH_IPV6;
        __builtin_memcpy(new_val.mac, fib.dmac, 6);
        __builtin_memcpy(new_val.dev_mac, fib.smac, 6);
        bpf_map_update_elem(&ip_mac_v6, &mac_key, &new_val, BPF_ANY);

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end) return XDP_PASS;
        __builtin_memcpy(eth->h_dest, fib.dmac, 6);
        __builtin_memcpy(eth->h_source, fib.smac, 6);
        return xdp_redirect_or_tc_handoff(ctx, fib.ifindex, meta->mark);
    }

    return xdp_redirect_or_tc_handoff(ctx, lan_info->ifindex, meta->mark);
}

// ── main XDP wan_route ingress ──

static __always_inline void xdp_setting_cache_in_wan_v4(struct xdp_md *ctx,
                                                        const struct route_context_v4 *context) {
    struct rt_cache_key_v4 cache_key = {
        .local_addr = context->daddr,
        .remote_addr = context->saddr,
    };

    u32 key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (lan_cache) {
        if (bpf_map_lookup_elem(lan_cache, &cache_key) != NULL) {
            bpf_printk("[wan_cache_w] v4 SKIP already in lan_cache local=%pI4 remote=%pI4",
                       &cache_key.local_addr, &cache_key.remote_addr);
            return;
        }
    }

    key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt4_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value_v4 *target = bpf_map_lookup_elem(wan_cache, &cache_key);
        if (target) {
            bpf_printk("[wan_cache_w] v4 UPDATE local=%pI4 remote=%pI4 ifindex=%u old_if=%u",
                       &cache_key.local_addr, &cache_key.remote_addr, ctx->ingress_ifindex,
                       target->ifindex);
            target->ifindex = ctx->ingress_ifindex;
            target->has_mac = 1;
            target->xdp_redirect_able = xdp_redirect_target_able(ctx->ingress_ifindex) ? 1 : 0;
        } else {
            bpf_printk("[wan_cache_w] v4 NEW local=%pI4 remote=%pI4 ifindex=%u has_mac=1",
                       &cache_key.local_addr, &cache_key.remote_addr, ctx->ingress_ifindex);
            struct rt_cache_value_v4 new_target = {};
            new_target.has_mac = 1;
            new_target.ifindex = ctx->ingress_ifindex;
            new_target.xdp_redirect_able = xdp_redirect_target_able(ctx->ingress_ifindex) ? 1 : 0;
            bpf_map_update_elem(wan_cache, &cache_key, &new_target, BPF_ANY);
        }
    }
}

static __always_inline void xdp_setting_cache_in_wan_v6(struct xdp_md *ctx,
                                                        const struct route_context_v6 *context) {
    struct rt_cache_key_v6 cache_key = {};
    __builtin_memcpy(cache_key.local_addr.bytes, context->daddr.bytes, 16);
    __builtin_memcpy(cache_key.remote_addr.bytes, context->saddr.bytes, 16);

    u32 key = LAN_CACHE;
    void *lan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (lan_cache) {
        if (bpf_map_lookup_elem(lan_cache, &cache_key) != NULL) {
            bpf_printk("[wan_cache_w] v6 SKIP already in lan_cache local=%pI6c remote=%pI6c",
                       &cache_key.local_addr, &cache_key.remote_addr);
            return;
        }
    }

    key = WAN_CACHE;
    void *wan_cache = bpf_map_lookup_elem(&rt6_cache_map, &key);
    if (wan_cache) {
        struct rt_cache_value_v6 *target = bpf_map_lookup_elem(wan_cache, &cache_key);
        if (target) {
            bpf_printk("[wan_cache_w] v6 UPDATE local=%pI6c remote=%pI6c ifindex=%u old_if=%u",
                       &cache_key.local_addr, &cache_key.remote_addr, ctx->ingress_ifindex,
                       target->ifindex);
            target->ifindex = ctx->ingress_ifindex;
            target->has_mac = 1;
            target->xdp_redirect_able = xdp_redirect_target_able(ctx->ingress_ifindex) ? 1 : 0;
        } else {
            bpf_printk("[wan_cache_w] v6 NEW local=%pI6c remote=%pI6c ifindex=%u has_mac=1",
                       &cache_key.local_addr, &cache_key.remote_addr, ctx->ingress_ifindex);
            struct rt_cache_value_v6 new_target = {};
            new_target.has_mac = 1;
            new_target.ifindex = ctx->ingress_ifindex;
            new_target.xdp_redirect_able = xdp_redirect_target_able(ctx->ingress_ifindex) ? 1 : 0;
            bpf_map_update_elem(wan_cache, &cache_key, &new_target, BPF_ANY);
        }
    }
}

SEC("xdp")
int xdp_wan_route_ingress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "xdp_wan_route_ingress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    int ret;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == ETH_IPV4) {
        struct route_context_v4 context = {};
        struct xdp_pipe_meta meta = {};
        ret = xdp_read_ipv4(ctx, &context);
        if (ret) return ret;
        ret = xdp_should_forward_v4(&context);
        if (ret) return ret;

        ret = xdp_is_wan_packet_v4(ctx, &context);
        if (ret) return ret;
        xdp_get_meta(ctx, &meta);

        ret = xdp_lan_redirect_v4(ctx, &context, &meta);
        if (ret && (ret != XDP_PASS || meta.mark == XDP_HANDOFF_TC_REDIRECT_MAGIC)) {
            if (get_cache_mask(meta.mark) == INGRESS_STATIC_MARK) {
                xdp_setting_cache_in_wan_v4(ctx, &context);
            }
        }
        return ret;
    } else if (eth->h_proto == ETH_IPV6) {
        struct route_context_v6 context = {};
        struct xdp_pipe_meta meta = {};
        ret = xdp_read_ipv6(ctx, &context);
        if (ret) return ret;
        ret = xdp_should_forward_v6(&context);
        if (ret) return ret;
        ret = xdp_is_wan_packet_v6(ctx, &context);
        if (ret) return ret;
        xdp_get_meta(ctx, &meta);
        ret = xdp_lan_redirect_v6(ctx, &context, &meta);
        if (ret && (ret != XDP_PASS || meta.mark == XDP_HANDOFF_TC_REDIRECT_MAGIC)) {
            if (get_cache_mask(meta.mark) == INGRESS_STATIC_MARK) {
                xdp_setting_cache_in_wan_v6(ctx, &context);
            }
        }
        return ret;
    }

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}
