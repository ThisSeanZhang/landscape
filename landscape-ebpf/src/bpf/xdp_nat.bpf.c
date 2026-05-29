#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "land_nat_common.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner4.h"
#include "scanner/xdp_scanner6.h"
#include "nat/xdp_nat4.h"
#include "nat/xdp_nat6.h"
#include "nat/xdp_nat6_v3.h"
#include "pipeline/pipeline.h"
#include "pipeline/xdp_wan_maps.h"
#include "pipeline/xdp_lan_maps.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;

static __always_inline int nat_v4_egress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v4_egress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv4_idx idx = {};
    if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    ret = is_handle_protocol(idx.l4_protocol);
    if (ret != TC_ACT_OK) return XDP_PASS;

    struct inet4_pair ip_pair = {};
    if (xdp_read_nat_info4(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) return XDP_PASS;

    if (xdp_frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                        &ip_pair.dst_port) != XDP_PASS)
        return XDP_DROP;

    bool is_icmpx_error = idx.l4_protocol == IPPROTO_ICMP && idx.icmp_error_l3_offset != 0;
    u8 nat_l4_protocol = is_icmpx_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;
    bool allow_create_mapping = !is_icmpx_error && pkt_allow_initiating_ct(idx.pkt_type);

    struct nat4_mapping_value_v3 *nat_egress_value = NULL;
    struct nat4_mapping_value_v3 *nat_ingress_value = NULL;
    struct nat4_port_queue_value_v3 alloc_item = {};
    bool created = false;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;
    ret = xdp_nat4_egress_lookup_or_new_mapping_v4(
        wan_if, meta.mark, nat_l4_protocol, allow_create_mapping, &ip_pair, &nat_egress_value,
        &nat_ingress_value, &alloc_item, &created);
    if (ret || !nat_egress_value || !nat_ingress_value) return XDP_DROP;

    bool is_dynamic = nat_egress_value->is_static == 0;
    bool is_ancestor = ip_pair.dst_addr.addr == nat_egress_value->trigger_addr &&
                       ip_pair.dst_port == nat_egress_value->trigger_port;

    if (is_dynamic && nat_egress_value->is_allow_reuse == 0 && nat_l4_protocol != IPPROTO_ICMP) {
        if (!is_ancestor) return XDP_DROP;
    }

    if (is_dynamic && is_ancestor) {
        u8 allow = get_flow_allow_reuse_port(meta.mark) ? 1 : 0;
        nat_egress_value->is_allow_reuse = allow;
        nat_ingress_value->is_allow_reuse = allow;
    }

    struct inet4_addr nat_addr = {
        .addr = nat_egress_value->addr,
    };
    __be16 nat_port = nat_egress_value->port;
    if (!is_dynamic) {
        struct wan_ip_info_key wan_search_key = {
            .ifindex = wan_if,
            .l3_protocol = LANDSCAPE_IPV4_TYPE,
        };
        struct wan_ip_info_value *wan_ip_info =
            bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
        if (!wan_ip_info) return XDP_DROP;
        nat_addr.addr = wan_ip_info->addr.ip;
    }

    struct inet4_pair server_nat_pair = {
        .src_addr = ip_pair.dst_addr,
        .src_port = ip_pair.dst_port,
        .dst_addr = nat_addr,
        .dst_port = nat_port,
    };
    if (nat_l4_protocol == IPPROTO_ICMP) {
        server_nat_pair.src_port = nat_port;
    }

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = xdp_nat4_lookup_or_new_ct_egress(
        data, data_end, meta.mark, wan_if, nat_l4_protocol, allow_create_mapping, &server_nat_pair,
        &ip_pair.src_addr, ip_pair.src_port, nat_ingress_value, &ct_value, &alloc_item,
        nat_addr.addr, nat_port, created, is_dynamic);

    if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) {
        if (created && is_dynamic &&
            nat_ingress_value->state_ref == nat4_v3_state_make(NAT4_V3_STATE_ACTIVE, 0)) {
            nat4_v3_delete_mapping_pair(nat_l4_protocol, nat_addr.addr, nat_port,
                                        ip_pair.src_addr.addr, ip_pair.src_port);
            (void)nat4_v3_queue_push(nat_l4_protocol, &alloc_item);
        }
        return XDP_DROP;
    }

    if (!is_icmpx_error) {
        ct_state_transition(idx.pkt_type, NAT_MAPPING_EGRESS, nat4_v3_timer_base(ct_value));
        void *d = (void *)(long)ctx->data;
        void *de = (void *)(long)ctx->data_end;
        xdp_nat4_metric_accumulate(d, de, ct_value, false);
    }

    struct nat_action_v4 action = {
        .from_addr = ip_pair.src_addr,
        .from_port = ip_pair.src_port,
        .to_addr = nat_addr,
        .to_port = nat_port,
    };

    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    if (xdp_modify_headers_v4(d, de, idx.l4_offset, idx.l4_protocol, true, &action, is_icmpx_error,
                              idx.icmp_error_l3_offset, idx.icmp_error_inner_l4_offset,
                              idx.icmp_error_l4_protocol))
        return XDP_DROP;

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

static __always_inline int nat_v4_ingress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v4_ingress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv4_idx idx = {};
    if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    ret = is_handle_protocol(idx.l4_protocol);
    if (ret != TC_ACT_OK) return XDP_PASS;

    struct inet4_pair ip_pair = {};
    if (xdp_read_nat_info4(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    ret = is_broadcast_ip4_pair(&ip_pair);
    if (ret != TC_ACT_OK) return XDP_PASS;

    if (xdp_frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                        &ip_pair.dst_port) != XDP_PASS)
        return XDP_DROP;

    bool is_icmpx_error = idx.l4_protocol == IPPROTO_ICMP && idx.icmp_error_l3_offset != 0;
    u8 nat_l4_protocol = is_icmpx_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;

    struct nat4_mapping_value_v3 *nat_ingress_value = NULL;

    struct nat_mapping_key_v4 ingress_key = {
        .gress = NAT_MAPPING_INGRESS,
        .l4proto = nat_l4_protocol,
        .from_port = ip_pair.dst_port,
        .from_addr = ip_pair.dst_addr.addr,
    };

    struct nat4_mapping_value_v3 *dynamic_value = bpf_map_lookup_elem(&nat4_dyn_map, &ingress_key);
    if (!dynamic_value) {
        ingress_key.from_addr = 0;
        nat_ingress_value = bpf_map_lookup_elem(&nat4_st_map, &ingress_key);
        if (!nat_ingress_value) return XDP_DROP;
    } else {
        struct nat_mapping_key_v4 egress_key = {
            .gress = NAT_MAPPING_EGRESS,
            .l4proto = nat_l4_protocol,
            .from_port = dynamic_value->port,
            .from_addr = dynamic_value->addr,
        };
        struct nat4_mapping_value_v3 *egress_value =
            bpf_map_lookup_elem(&nat4_dyn_map, &egress_key);
        if (!egress_value || egress_value->addr != ip_pair.dst_addr.addr ||
            egress_value->port != ip_pair.dst_port) {
            bpf_map_delete_elem(&nat4_dyn_map, &ingress_key);
            return XDP_DROP;
        }
        nat_ingress_value = dynamic_value;
    }

    bool is_static = nat_ingress_value->is_static != 0;

    if (!is_static && nat_ingress_value->is_allow_reuse == 0 && nat_l4_protocol != IPPROTO_ICMP) {
        if (ip_pair.src_addr.addr != nat_ingress_value->trigger_addr ||
            ip_pair.src_port != nat_ingress_value->trigger_port) {
            return XDP_DROP;
        }
    }

    if (is_static) {
        meta.mark = replace_cache_mask(meta.mark, INGRESS_STATIC_MARK);
        void *dm = (void *)(long)ctx->data_meta;
        if (dm + sizeof(meta) <= data)
            __builtin_memcpy(dm, &meta, sizeof(meta));
        else
            xdp_set_meta(ctx, &meta);
    }

    struct inet4_addr lan_ip = {0};
    __be16 lan_port = 0;
    if (is_static && nat_ingress_value->addr == 0) {
        lan_ip.addr = ip_pair.dst_addr.addr;
    } else {
        lan_ip.addr = nat_ingress_value->addr;
    }
    lan_port = nat_ingress_value->port;

    struct inet4_pair server_nat_pair = {
        .src_addr = ip_pair.src_addr,
        .src_port = ip_pair.src_port,
        .dst_addr = ip_pair.dst_addr,
        .dst_port = ip_pair.dst_port,
    };

    u64 ingress_state_ref = nat_ingress_value->state_ref;
    bool do_new_ct = is_static ? (!is_icmpx_error && pkt_allow_initiating_ct(idx.pkt_type))
                               : (nat_ingress_value->is_allow_reuse &&
                                  nat4_v3_state_get(ingress_state_ref) == NAT4_V3_STATE_ACTIVE &&
                                  nat4_v3_ref_get(ingress_state_ref) > 0 && !is_icmpx_error &&
                                  pkt_allow_initiating_ct(idx.pkt_type));

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = xdp_nat4_lookup_or_new_ct_ingress(data, data_end, meta.mark, current_ifindex,
                                            nat_l4_protocol, do_new_ct, &server_nat_pair, &lan_ip,
                                            lan_port, nat_ingress_value, &ct_value);

    if (ret == TIMER_NOT_FOUND || ret == TIMER_ERROR) return XDP_DROP;

    if (!is_icmpx_error) {
        ct_state_transition(idx.pkt_type, NAT_MAPPING_INGRESS, nat4_v3_timer_base(ct_value));
        void *d = (void *)(long)ctx->data;
        void *de = (void *)(long)ctx->data_end;
        xdp_nat4_metric_accumulate(d, de, ct_value, true);
    }

    struct nat_action_v4 action = {
        .from_addr = ip_pair.dst_addr,
        .from_port = ip_pair.dst_port,
        .to_addr = lan_ip,
        .to_port = lan_port,
    };

    void *d = (void *)(long)ctx->data;
    void *de = (void *)(long)ctx->data_end;
    if (xdp_modify_headers_v4(d, de, idx.l4_offset, idx.l4_protocol, false, &action, is_icmpx_error,
                              idx.icmp_error_l3_offset, idx.icmp_error_inner_l4_offset,
                              idx.icmp_error_l4_protocol))
        return XDP_DROP;

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

static __always_inline int nat_v6_egress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v6_egress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    ret = is_handle_protocol(idx.l4_protocol);
    if (ret != TC_ACT_OK) return XDP_PASS;

    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    struct inet_pair ip_pair = {};
    if (xdp_read_nat_info6(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    __be16 sport = ip_pair.src_port;
    __be16 dport = ip_pair.dst_port;

    if (xdp_frag6_track(&idx, &ip6h->saddr, &ip6h->daddr, &sport, &dport) != XDP_PASS)
        return XDP_DROP;
    ip_pair.src_port = sport;
    ip_pair.dst_port = dport;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    ret =
        xdp_ipv6_egress_prefix_check_and_replace(data, data_end, wan_if, meta.mark, &idx, &ip_pair);
    if (ret) return XDP_DROP;

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

static __always_inline int nat_v6_ingress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v6_ingress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    ret = is_handle_protocol(idx.l4_protocol);
    if (ret != TC_ACT_OK) return XDP_PASS;

    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    struct inet_pair ip_pair = {};
    if (xdp_read_nat_info6(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    __be16 sport = ip_pair.src_port;
    __be16 dport = ip_pair.dst_port;

    if (xdp_frag6_track(&idx, &ip6h->saddr, &ip6h->daddr, &sport, &dport) != XDP_PASS)
        return XDP_DROP;
    ip_pair.src_port = sport;
    ip_pair.dst_port = dport;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    bool is_static = false;
    ret = xdp_ipv6_ingress_prefix_check_and_replace(data, data_end, wan_if, meta.mark, &idx,
                                                    &ip_pair, &is_static);
    if (ret == -1) return XDP_DROP;
    if (ret == 1) {
        meta.mark = replace_cache_mask(meta.mark, INGRESS_STATIC_MARK);
        void *dm = (void *)(long)ctx->data_meta;
        if (dm + sizeof(meta) <= data)
            __builtin_memcpy(dm, &meta, sizeof(meta));
        else
            xdp_set_meta(ctx, &meta);
    }
    if (ret == 2) return XDP_PASS;

    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

static __always_inline void xdp_nat_tailcall(struct xdp_md *ctx, bool is_egress) {
    if (is_egress) {
        bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
        bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);
    } else {
        bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_WAN);
        bpf_tail_call(ctx, &xdp_pipe_exits_wan, 0);
    }
}

SEC("xdp")
int egress_nat(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "egress_nat"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    int ret = XDP_PASS;
    if (eth->h_proto == ETH_IPV4) {
        ret = nat_v4_egress(ctx);
    } else if (eth->h_proto == ETH_IPV6) {
        ret = nat_v6_egress(ctx);
    }
    if (ret != XDP_PASS) return ret;
    xdp_nat_tailcall(ctx, true);
    return XDP_PASS;
#undef BPF_LOG_TOPIC
}

SEC("xdp")
int ingress_nat(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "ingress_nat"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    int ret = XDP_PASS;
    if (eth->h_proto == ETH_IPV4) {
        ret = nat_v4_ingress(ctx);
    } else if (eth->h_proto == ETH_IPV6) {
        ret = nat_v6_ingress(ctx);
    }
    if (ret != XDP_PASS) return ret;
    xdp_nat_tailcall(ctx, false);
    return XDP_PASS;
#undef BPF_LOG_TOPIC
}
