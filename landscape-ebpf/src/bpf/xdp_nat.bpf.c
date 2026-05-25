#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner4.h"
#include "scanner/xdp_scanner6.h"
#include "nat/xdp_nat4.h"
#include "nat/xdp_nat6.h"
#include "pipeline/pipeline.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;

static __always_inline bool is_broadcast_or_zero_ip4(__be32 addr) {
    return addr == 0xffffffff || addr == 0;
}

static __always_inline int xdp_nat_v4(struct xdp_md *ctx, bool is_egress) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv4_idx idx;
    if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_PASS;

    u8 l4_proto = idx.l4_protocol;
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP && l4_proto != IPPROTO_ICMP)
        return XDP_PASS;

    struct inet4_pair pair = {};
    if (xdp_read_nat_info4(data, data_end, idx.l4_offset, l4_proto, &pair, idx.fragment_type))
        return XDP_PASS;

    if (is_broadcast_or_zero_ip4(pair.src_addr.addr) ||
        is_broadcast_or_zero_ip4(pair.dst_addr.addr))
        return XDP_PASS;

    if (xdp_frag4_track(&idx, pair.src_addr.addr, pair.dst_addr.addr, &pair.src_port,
                        &pair.dst_port) != XDP_PASS)
        return XDP_PASS;

    if (idx.fragment_type >= FRAG_MIDDLE) return XDP_PASS;

    bool is_icmpx_error = l4_proto == IPPROTO_ICMP && idx.icmp_error_l3_offset != 0;
    u8 nat_l4_proto = is_icmpx_error ? idx.icmp_error_l4_protocol : l4_proto;
    if (nat_l4_proto != IPPROTO_TCP && nat_l4_proto != IPPROTO_UDP && nat_l4_proto != IPPROTO_ICMP)
        return XDP_PASS;

    bool allow_create_ct = !is_icmpx_error && pkt_allow_initiating_ct(idx.pkt_type);

    struct nat4_mapping_value_v3 *egress = NULL;
    struct nat4_mapping_value_v3 *ingress = NULL;
    struct nat4_port_queue_value_v3 alloc_item = {};
    bool created = false;

    if (is_egress) {
        int ret = xdp_nat4_static_egress_lookup(nat_l4_proto, &pair, &egress, &ingress);
        if (ret && allow_create_ct) {
            u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;
            ret = xdp_nat4_dyn_egress_lookup(wan_if, meta.mark, nat_l4_proto, &pair, &egress,
                                             &ingress, &created);
        }
        if (ret) return XDP_PASS;

        if (egress->is_static == 0 && egress->is_allow_reuse == 0 && nat_l4_proto != IPPROTO_ICMP) {
            bool is_ancestor =
                pair.dst_addr.addr == egress->trigger_addr && pair.dst_port == egress->trigger_port;
            if (!is_ancestor) return XDP_PASS;
        }

        if (egress->is_static == 0 && created) {
            u8 allow = get_flow_allow_reuse_port(meta.mark) ? 1 : 0;
            egress->is_allow_reuse = allow;
            ingress->is_allow_reuse = allow;
        }
    } else {
        int ret = xdp_nat4_static_ingress_lookup(nat_l4_proto, &pair, &ingress);
        if (ret) {
            struct nat_mapping_key_v4 ingress_key = {
                .gress = NAT_MAPPING_INGRESS,
                .l4proto = nat_l4_proto,
                .from_port = pair.dst_port,
                .from_addr = pair.dst_addr.addr,
            };
            ingress = bpf_map_lookup_elem(&nat4_dyn_map, &ingress_key);
            if (ingress && ingress->is_static == 0) {
                struct nat_mapping_key_v4 egress_key = {
                    .gress = NAT_MAPPING_EGRESS,
                    .l4proto = nat_l4_proto,
                    .from_port = ingress->port,
                    .from_addr = ingress->addr,
                };
                struct nat4_mapping_value_v3 *egress_val =
                    bpf_map_lookup_elem(&nat4_dyn_map, &egress_key);
                if (!egress_val || egress_val->addr != pair.dst_addr.addr ||
                    egress_val->port != pair.dst_port) {
                    bpf_map_delete_elem(&nat4_dyn_map, &ingress_key);
                    ingress = NULL;
                }
            }
        }
        if (!ingress) return XDP_PASS;
        if (!ingress->is_static && ingress->is_allow_reuse == 0 && nat_l4_proto != IPPROTO_ICMP) {
            if (pair.src_addr.addr != ingress->trigger_addr ||
                pair.src_port != ingress->trigger_port)
                return XDP_PASS;
        }

        if (ingress->is_static) {
            meta.mark = replace_cache_mask(meta.mark, INGRESS_STATIC_MARK);
            void *dm = (void *)(long)ctx->data_meta;
            if (dm + sizeof(meta) <= data) __builtin_memcpy(dm, &meta, sizeof(meta));
        }
    }

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;
    struct nat_action_v4 action = {};
    __be32 nat_addr = 0;
    __be16 nat_port = 0;

    if (is_egress) {
        action.from_addr = pair.src_addr;
        action.from_port = pair.src_port;
        if (egress->is_static) {
            struct wan_ip_info_key wan_key = {
                .ifindex = wan_if,
                .l3_protocol = LANDSCAPE_IPV4_TYPE,
            };
            struct wan_ip_info_value *wan_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
            if (!wan_info) return XDP_PASS;
            action.to_addr.addr = wan_info->addr.ip;
        } else {
            action.to_addr.addr = egress->addr;
        }
        action.to_port = egress->port;
        nat_addr = action.to_addr.addr;
        nat_port = action.to_port;

        struct inet4_pair server_pair = {
            .src_addr = pair.dst_addr,
            .src_port = pair.dst_port,
            .dst_addr = action.to_addr,
            .dst_port = nat_port,
        };

        struct nat4_timer_value_v3 *ct_value = NULL;
        int ct_ret = xdp_nat4_lookup_or_new_ct_egress(
            data, data_end, meta.mark, wan_if, nat_l4_proto, allow_create_ct, &server_pair,
            &pair.src_addr, pair.src_port, ingress, &ct_value, &alloc_item, nat_addr, nat_port,
            created, egress->is_static == 0);

        if (ct_ret == TIMER_NOT_FOUND || ct_ret == TIMER_ERROR) {
            if (created && egress->is_static == 0) {
                xdp_nat4_egress_ct_cleanup(nat_l4_proto, nat_addr, nat_port, pair.src_addr.addr,
                                           pair.src_port, created, egress->is_static == 0, ingress,
                                           &alloc_item);
            }
            if (!created && egress->is_static) {
                goto skip_ct;
            }
            return XDP_PASS;
        }

        if (!is_icmpx_error) {
            ct_state_transition(idx.pkt_type, NAT_MAPPING_EGRESS, nat4_v3_timer_base(ct_value));
            xdp_nat4_metric_accumulate(data, data_end, ct_value, false);
        }
    skip_ct:;
    } else {
        action.from_addr = pair.dst_addr;
        action.from_port = pair.dst_port;
        bool is_static = ingress->is_static != 0;

        struct inet4_addr lan_ip = {0};
        __be16 lan_port = 0;
        if (is_static && ingress->addr == 0) {
            lan_ip.addr = pair.dst_addr.addr;
        } else {
            lan_ip.addr = ingress->addr;
        }
        lan_port = ingress->port;

        action.to_addr = lan_ip;
        action.to_port = lan_port;

        struct inet4_pair server_pair = {
            .src_addr = pair.src_addr,
            .src_port = pair.src_port,
            .dst_addr = pair.dst_addr,
            .dst_port = pair.dst_port,
        };

        u64 ingress_state_ref = ingress->state_ref;
        bool do_new_ct = is_static
                             ? (!is_icmpx_error && pkt_allow_initiating_ct(idx.pkt_type))
                             : (ingress->is_allow_reuse &&
                                nat4_v3_state_get(ingress_state_ref) == NAT4_V3_STATE_ACTIVE &&
                                nat4_v3_ref_get(ingress_state_ref) > 0 && !is_icmpx_error &&
                                pkt_allow_initiating_ct(idx.pkt_type));

        struct nat4_timer_value_v3 *ct_value = NULL;
        int ct_ret = xdp_nat4_lookup_or_new_ct_ingress(data, data_end, meta.mark, current_ifindex,
                                                       nat_l4_proto, do_new_ct, &server_pair,
                                                       &lan_ip, lan_port, ingress, &ct_value);

        if (ct_ret == TIMER_NOT_FOUND || ct_ret == TIMER_ERROR) {
            if (is_static) {
                goto skip_ct_ingress;
            }
            return XDP_PASS;
        }

        if (!is_icmpx_error) {
            ct_state_transition(idx.pkt_type, NAT_MAPPING_INGRESS, nat4_v3_timer_base(ct_value));
            xdp_nat4_metric_accumulate(data, data_end, ct_value, true);
        }
    skip_ct_ingress:;
    }

    xdp_modify_headers_v4(data, data_end, idx.l4_offset, l4_proto, is_egress, &action,
                          is_icmpx_error, idx.icmp_error_l3_offset, idx.icmp_error_inner_l4_offset,
                          idx.icmp_error_l4_protocol);

    return XDP_PASS;
}

static __always_inline int xdp_nat_v6(struct xdp_md *ctx, bool is_egress) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct xdp_ipv6_idx idx;
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_PASS;

    u8 l4_proto = idx.l4_protocol;
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) return XDP_PASS;

    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

    struct inet_pair pair6 = {};
    if (xdp_read_nat_info6(data, data_end, idx.l4_offset, l4_proto, &pair6, idx.fragment_type))
        return XDP_PASS;

    __be16 sport = pair6.src_port;
    __be16 dport = pair6.dst_port;

    if (xdp_frag6_track(&idx, &ip6h->saddr, &ip6h->daddr, &sport, &dport) != XDP_PASS)
        return XDP_PASS;

    if (idx.fragment_type >= FRAG_MIDDLE) return XDP_PASS;

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;

    if (is_egress) {
        __be64 old_prefix;
        if (xdp_nat6_egress_prefix_replace(ctx, wan_if, ip6h, &old_prefix)) return XDP_PASS;

        __be64 new_prefix;
        __builtin_memcpy(&new_prefix, &ip6h->saddr, sizeof(new_prefix));
        xdp_nat6_update_l4_checksum(data, data_end, idx.l4_offset, l4_proto, old_prefix,
                                    new_prefix);
    } else {
        if (!xdp_nat6_ingress_prefix_replace(ctx, wan_if, ip6h, idx.l4_offset, l4_proto)) {
            meta.mark = replace_cache_mask(meta.mark, INGRESS_STATIC_MARK);
            void *dm = (void *)(long)ctx->data_meta;
            if (dm + sizeof(meta) <= data) __builtin_memcpy(dm, &meta, sizeof(meta));
        }
    }

    return XDP_PASS;
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
int xdp_nat_lan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == ETH_IPV4) {
        xdp_nat_v4(ctx, true);
    } else if (eth->h_proto == ETH_IPV6) {
        xdp_nat_v6(ctx, true);
    }
    xdp_nat_tailcall(ctx, true);
    return XDP_PASS;
}

SEC("xdp")
int xdp_nat_wan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == ETH_IPV4) {
        xdp_nat_v4(ctx, false);
    } else if (eth->h_proto == ETH_IPV6) {
        xdp_nat_v6(ctx, false);
    }
    xdp_nat_tailcall(ctx, false);
    return XDP_PASS;
}
