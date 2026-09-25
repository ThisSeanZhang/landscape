#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "nat/nat_common.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner4.h"
#include "scanner/xdp_scanner6.h"
#include "nat/xdp_nat4.h"
#include "nat/xdp_nat6.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"
#include "chain/xdp_stage.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u32 current_ifindex = 0;
// Chain identity for directly-attached instances (tests, standalone tools)
// where no intro program stores the chain id in XDP metadata. Inside a chain
// the meta is always set by the intro, so this fallback never fires.
const volatile u32 current_chain_id = 0;

static __always_inline void xdp_apply_ingress_static_mark(struct xdp_md *ctx,
                                                          struct xdp_pipe_meta *meta, void *data) {
    meta->mark = replace_cache_mask(meta->mark, INGRESS_STATIC_MARK);
    void *dm = (void *)(long)ctx->data_meta;
    if ((void *)(dm + sizeof(*meta)) <= data)
        __builtin_memcpy(dm, meta, sizeof(*meta));
    else
        xdp_set_meta(ctx, meta);
}

static __always_inline int nat_v4_egress(struct xdp_md *ctx) {
#define BPF_LOG_TOPIC "nat_v4_egress"
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_pipe_meta meta = {};
    xdp_get_meta(ctx, &meta);

    struct scan_ipv4_idx idx = {};
    if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

    struct inet4_pair ip_pair = {};
    if (xdp_read_nat_info4(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    if (unlikely(is_broadcast_ip4_pair(&ip_pair))) {
        return XDP_PASS;
    }

    if (xdp_frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                        &ip_pair.dst_port) != XDP_PASS)
        return XDP_DROP;

    bool is_icmp_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    u8 nat_l4_protocol = is_icmp_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;
    bool allow_create_mapping = !is_icmp_error && pkt_can_begin_ct(idx.pkt_type);

    struct nat4_egress_result result = {};
    struct nat4_mapping_value_v3 *dyn_ingress = NULL;
    struct nat4_port_queue_value_v3 alloc_item = {};

    u32 wan_if = meta.target_ifindex ? meta.target_ifindex : current_ifindex;
    // wan_ip_binding is keyed by the logical chain id.  Never fall back to the
    // ifindex here: ifindices and chain ids share the same small-integer
    // space, and a collision would silently NAT with the wrong WAN address.
    u32 wan_chain = meta.chain_id ? meta.chain_id : current_chain_id;
    ret = xdp_nat4_st_egress_lookup(wan_chain, nat_l4_protocol, &ip_pair, &result);
    if (ret) {
        ret = xdp_nat4_dyn_egress_lookup_and_check(wan_chain, meta.mark, nat_l4_protocol,
                                                   allow_create_mapping, &ip_pair, &result,
                                                   &dyn_ingress, &alloc_item);
        if (ret) return XDP_DROP;
    }

    struct nat4_timer_key ct_key = {0};
    ct_key.l4proto = nat_l4_protocol;
    ct_key.pair_ip.src_addr = ip_pair.dst_addr;
    ct_key.pair_ip.src_port = ip_pair.dst_port;
    ct_key.pair_ip.dst_addr.addr = result.nat_addr;
    ct_key.pair_ip.dst_port = result.nat_port;
    if (nat_l4_protocol == IPPROTO_ICMP) {
        ct_key.pair_ip.src_port = result.nat_port;
    }

    struct nat4_timer_value_v3 *ct_value = NULL;
    ret = xdp_nat4_ct_resolve(&ct_key, dyn_ingress, &ct_value);
    if (ret && allow_create_mapping) {
        ret = xdp_nat4_ct_create(meta.mark, wan_if, &ct_key, &ip_pair.src_addr, ip_pair.src_port,
                                 NAT_MAPPING_EGRESS, dyn_ingress, &ct_value);
        if (ret) {
            if (result.is_created && dyn_ingress &&
                dyn_ingress->state_ref == nat4_state_make(NAT4_STATE_ACTIVE, 0)) {
                nat4_delete_mapping_pair(nat_l4_protocol, result.nat_addr, result.nat_port,
                                         ip_pair.src_addr.addr, ip_pair.src_port);
                (void)nat4_queue_push(nat_l4_protocol, &alloc_item);
            }
            return XDP_DROP;
        }
    } else if (ret) {
        return XDP_DROP;
    }

    if (!is_icmp_error) {
        nat4_ct_advance(idx.pkt_type, NAT_MAPPING_EGRESS, ct_value);
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        xdp_nat4_metric_accumulate(data, data_end, ct_value, false);
    }

    struct nat4_action action = {
        .from_addr = ip_pair.src_addr,
        .from_port = ip_pair.src_port,
        .to_addr.addr = result.nat_addr,
        .to_port = result.nat_port,
    };

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (xdp_modify_headers_v4(data, data_end, idx.l4_offset, idx.l4_protocol, true, &action,
                              is_icmp_error, idx.icmp_error_l3_offset,
                              idx.icmp_error_inner_l4_offset, idx.icmp_error_l4_protocol))
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

    struct scan_ipv4_idx idx = {};
    if (xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

    struct inet4_pair ip_pair = {};
    if (xdp_read_nat_info4(data, data_end, &idx, &ip_pair)) return XDP_DROP;

    if (unlikely(is_broadcast_ip4_pair(&ip_pair))) {
        return XDP_PASS;
    }

    if (xdp_frag4_track(&idx, ip_pair.src_addr.addr, ip_pair.dst_addr.addr, &ip_pair.src_port,
                        &ip_pair.dst_port) != XDP_PASS)
        return XDP_DROP;

    bool is_icmp_error = idx.icmp_error_l3_offset > 0 && idx.icmp_error_inner_l4_offset > 0;
    u8 nat_l4_protocol = is_icmp_error ? idx.icmp_error_l4_protocol : idx.l4_protocol;

    struct nat4_lan_result result = {};
    struct nat4_mapping_value_v3 *dyn_ingress = NULL;
    struct nat4_action action = {0};

    struct nat4_timer_key ct_key = {0};
    ct_key.l4proto = nat_l4_protocol;
    ct_key.pair_ip.src_addr = ip_pair.src_addr;
    ct_key.pair_ip.src_port = ip_pair.src_port;
    ct_key.pair_ip.dst_addr = ip_pair.dst_addr;
    ct_key.pair_ip.dst_port = ip_pair.dst_port;

    struct nat4_timer_value_v3 *ct_value = NULL;

    enum ct_ingress_resolve cr = xdp_nat4_ct_ingress_resolve(&ct_key, &ct_value);
    if (cr == CT_RESOLVE_UNUSABLE) {
        return XDP_DROP;
    }
    if (cr == CT_RESOLVE_OK) {
        if (ct_value->is_static) {
            xdp_apply_ingress_static_mark(ctx, &meta, data);
        }
        action.to_addr.addr = ct_value->client_addr.addr;
        action.to_port = ct_value->client_port;
        goto translate;
    }

    bool allow_create_ct = !is_icmp_error && pkt_can_begin_ct(idx.pkt_type);
    if (!allow_create_ct) return XDP_DROP;

    ret = xdp_nat4_st_ingress_lookup(nat_l4_protocol, &ip_pair, &result);
    if (ret == 0) {
        xdp_apply_ingress_static_mark(ctx, &meta, data);
    } else {
        ret =
            xdp_nat4_dyn_ingress_lookup_and_check(nat_l4_protocol, &ip_pair, &result, &dyn_ingress);
        if (ret) return XDP_DROP;
        if (!nat4_can_create_ct(dyn_ingress)) return XDP_DROP;
    }

    if (dyn_ingress == NULL && result.lan_addr == 0) {
        action.to_addr.addr = ip_pair.dst_addr.addr;
    } else {
        action.to_addr.addr = result.lan_addr;
    }
    action.to_port = result.lan_port;
    ret = xdp_nat4_ct_create(meta.mark, current_ifindex, &ct_key, &action.to_addr, result.lan_port,
                             NAT_MAPPING_INGRESS, dyn_ingress, &ct_value);
    if (ret) return XDP_DROP;

translate:
    action.from_addr = ip_pair.dst_addr;
    action.from_port = ip_pair.dst_port;

    if (!is_icmp_error) {
        nat4_ct_advance(idx.pkt_type, NAT_MAPPING_INGRESS, ct_value);
        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        xdp_nat4_metric_accumulate(data, data_end, ct_value, true);
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (xdp_modify_headers_v4(data, data_end, idx.l4_offset, idx.l4_protocol, false, &action,
                              is_icmp_error, idx.icmp_error_l3_offset,
                              idx.icmp_error_inner_l4_offset, idx.icmp_error_l4_protocol))
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

    struct scan_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

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
    u32 wan_chain = meta.chain_id ? meta.chain_id : current_chain_id;

    ret = xdp_ipv6_egress_prefix_check_and_replace(data, data_end, wan_chain, wan_if, meta.mark,
                                                   &idx, &ip_pair);
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

    struct scan_ipv6_idx idx = {};
    if (xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &idx)) return XDP_DROP;

    int ret;
    if (unlikely(should_nat_skip_protocol(idx.l4_protocol))) {
        return XDP_PASS;
    }

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
    u32 wan_chain = meta.chain_id ? meta.chain_id : current_chain_id;

    bool is_static = false;
    ret = xdp_ipv6_ingress_prefix_check_and_replace(data, data_end, wan_chain, wan_if, meta.mark,
                                                    &idx, &ip_pair, &is_static);
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
