#ifndef __LD_XDP_NAT6_H__
#define __LD_XDP_NAT6_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "base/tcp_phase.h"
#include "nat/nat_common.h"
#include "nat/nat6_map_ops.h"
#include "nat/nat6_ct_timer.h"
#include "nat/nat_rodata.h"
#include "nat/xdp_csum_helpers.h"
#include "reader/xdp_nat_view.h"

static __always_inline u8 xdp_nat6_outer_protocol(const struct xdp_nat_view *view) {
    return view->icmp_inner_l4_offset ? NEXTHDR_ICMP : view->l4_protocol;
}

static __always_inline bool xdp_nat6_is_icmp_error(const struct xdp_nat_view *view) {
    return view->icmp_inner_l4_offset != 0;
}

static __always_inline u16 xdp_nat6_icmp_error_l3_offset(const struct xdp_nat_view *view) {
    return view->icmp_inner_l4_offset ? (u16)(view->l4_offset + sizeof(struct icmp6hdr)) : 0;
}

static __always_inline void xdp_nat6_metric_accumulate(void *data, void *data_end, bool ingress,
                                                       struct nat6_timer_value *value) {
    u64 bytes = (u64)(long)data_end - (u64)(long)data;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline int xdp_update_ipv6_cache_value(u32 mark, const struct xdp_nat_view *view,
                                                       const struct in6_addr *src_addr,
                                                       const struct in6_addr *dst_addr,
                                                       struct nat6_timer_value *value) {
    COPY_ADDR_FROM(value->client_prefix, src_addr->in6_u.u6_addr8);
    if (!value->is_static) {
        bool is_ancestor =
            ip_addr_equal_x(dst_addr, &value->trigger_addr) && view->dport == value->trigger_port;
        if (is_ancestor) {
            bool allow_reuse_port = get_flow_allow_reuse_port(mark);
            value->is_allow_reuse = allow_reuse_port ? 1 : 0;
        }
    }
    value->flow_id = get_flow_id(mark);
    return 0;
}

static __always_inline struct nat6_timer_value *
xdp_lookup_ct6_ingress(const struct xdp_nat_view *view, const struct in6_addr *dst_addr,
                       u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = view->dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = xdp_nat6_outer_protocol(view);

    return bpf_map_lookup_elem(&nat6_timer_map, &key);
}

static __always_inline struct nat6_timer_value *
xdp_create_ct6_ingress(u32 wan_if, u32 mark, const struct xdp_nat_view *view,
                       const struct in6_addr *src_addr, const struct in6_addr *dst_addr,
                       u8 npt_id_mask, const __be64 *client_prefix_hint, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = view->dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = xdp_nat6_outer_protocol(view);

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(mark);
    new_value.gress = NAT_MAPPING_INGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = wan_if;
    COPY_ADDR_FROM(new_value.trigger_addr.in6_u.u6_addr8, src_addr->in6_u.u6_addr32);
    new_value.trigger_port = view->sport;
    COPY_ADDR_FROM(new_value.client_prefix, client_prefix_hint);
    new_value.is_allow_reuse = 1;
    new_value.is_static = 1;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline struct nat6_timer_value *
xdp_lookup_ct6_egress(u32 mark, const struct xdp_nat_view *view, const struct in6_addr *src_addr,
                      const struct in6_addr *dst_addr, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = view->sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = xdp_nat6_outer_protocol(view);

    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (value) {
        if (!nat6_is_same_prefix(value->client_prefix, src_addr, npt_id_mask)) {
            xdp_update_ipv6_cache_value(mark, view, src_addr, dst_addr, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat6_timer_value *
xdp_create_ct6_egress(u32 wan_if, u32 mark, const struct xdp_nat_view *view,
                      const struct in6_addr *src_addr, const struct in6_addr *dst_addr,
                      u8 npt_id_mask, u8 is_allow_reuse, bool is_static, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = view->sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = xdp_nat6_outer_protocol(view);

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(mark);
    new_value.gress = NAT_MAPPING_EGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = wan_if;
    COPY_ADDR_FROM(new_value.client_prefix, src_addr->in6_u.u6_addr8);
    new_value.is_allow_reuse = is_allow_reuse;
    new_value.is_static = is_static ? 1 : 0;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;
    COPY_ADDR_FROM(new_value.trigger_addr.in6_u.u6_addr32, dst_addr->in6_u.u6_addr32);
    new_value.trigger_port = view->dport;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline int xdp_ipv6_egress_prefix_check_and_replace(
    struct xdp_md *ctx, void *data, void *data_end, u32 l3_offset, u32 wan_if, u32 mark,
    const struct xdp_nat_view *view, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr) {
    u8 proto = xdp_nat6_outer_protocol(view);

    if (wan_ro_prefix6.b[0] == 0) return -1;

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);

    bool is_icmpx_error = xdp_nat6_is_icmp_error(view);

    struct nat6_timer_value *ct_value =
        xdp_lookup_ct6_egress(mark, view, src_addr, dst_addr, npt_id_mask);
    if (ct_value) {
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, false, ct_value);
        if (!ct_value->need_prefix_replace) return 0;
        goto do_xdp_nptv6;
    }

    struct static_nat6_mapping_value *static_val =
        nat6_check_egress_static(proto, src_addr, view->sport);

    bool allow_create = nat6_allows_create_pkt(proto, view->tcp_phase, is_icmpx_error);

    if (!allow_create) {
        if (!static_val) return -1;
        if (!nat6_static_needs_prefix_replace(static_val)) return 0;
        goto do_xdp_nptv6;
    }

    bool need_prefix_replace = static_val ? nat6_static_needs_prefix_replace(static_val) : true;
    u8 reuse = static_val ? 1 : (get_flow_allow_reuse_port(mark) ? 1 : 0);
    ct_value = xdp_create_ct6_egress(wan_if, mark, view, src_addr, dst_addr, npt_id_mask, reuse,
                                     static_val != NULL, need_prefix_replace);
    if (!ct_value) return -1;
    nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
    xdp_nat6_metric_accumulate(data, data_end, false, ct_value);
    if (!need_prefix_replace) return 0;

do_xdp_nptv6:
    if (is_icmpx_error) {
        u32 err_sender_off = l3_offset + offsetof(struct ipv6hdr, saddr);
        __be64 old_sender_prefix;
        if (bpf_xdp_load_bytes(ctx, err_sender_off, &old_sender_prefix, sizeof(old_sender_prefix)))
            return -1;

        u32 inner_dst_off = xdp_nat6_icmp_error_l3_offset(view) + offsetof(struct ipv6hdr, daddr);
        u32 inner_l4_csum_off = 0;
        if (nat6_l4_checksum(view->icmp_inner_l4_offset, view->icmp_inner_l4_protocol,
                             &inner_l4_csum_off))
            return -1;
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_csum_off)) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, src_addr->in6_u.u6_addr32, 8);

        __be64 new_ip_prefix =
            (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __be64 new_sender_prefix =
            (old_sender_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __be16 old_inner_l4_csum;
        if (bpf_xdp_load_bytes(ctx, inner_l4_csum_off, &old_inner_l4_csum,
                               sizeof(old_inner_l4_csum)))
            return -1;

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);
        __be16 new_inner_l4_csum = xdp_csum_apply(old_inner_l4_csum, addr_delta);

        __be16 outer_csum;
        if (bpf_xdp_load_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
        outer_csum = xdp_csum_apply(outer_csum, addr_delta);

        if (bpf_xdp_store_bytes(ctx, inner_l4_csum_off, &new_inner_l4_csum,
                                sizeof(new_inner_l4_csum)))
            return -1;
        if (bpf_xdp_store_bytes(ctx, inner_dst_off, &new_ip_prefix, sizeof(new_ip_prefix)))
            return -1;

        __be32 old_ic32 = (__be32)old_inner_l4_csum;
        __be32 new_ic32 = (__be32)new_inner_l4_csum;
        __wsum ic_delta = bpf_csum_diff(&old_ic32, 4, &new_ic32, 4, 0);
        outer_csum = xdp_csum_apply(outer_csum, ic_delta);

        if (bpf_xdp_store_bytes(ctx, err_sender_off, &new_sender_prefix, sizeof(new_sender_prefix)))
            return -1;
        __wsum sender_delta =
            bpf_csum_diff((__u32 *)&old_sender_prefix, 8, (__u32 *)&new_sender_prefix, 8, 0);
        outer_csum = xdp_csum_apply(outer_csum, sender_delta);
        if (bpf_xdp_store_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
    } else {
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_csum_off)) return -1;

        u32 ip_src_off = l3_offset + offsetof(struct ipv6hdr, saddr);
        void *src_ptr = data + ip_src_off;
        if (src_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, src_addr->in6_u.u6_addr32, 8);

        __be64 new_ip_prefix =
            (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __builtin_memcpy(src_ptr, &new_ip_prefix, 8);

        __be16 *csum_ptr = data + l4_csum_off;
        if ((void *)(csum_ptr + 1) > data_end) return -1;
        __wsum delta = bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);
        *csum_ptr = xdp_csum_apply(*csum_ptr, delta);
    }

    return 0;
}

static __always_inline int xdp_ipv6_ingress_prefix_check_and_replace(
    struct xdp_md *ctx, void *data, void *data_end, u32 l3_offset, u32 wan_if, u32 mark,
    const struct xdp_nat_view *view, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, bool *out_is_static) {
    __be64 local_client_prefix = {0};
    u8 proto = xdp_nat6_outer_protocol(view);

    if (wan_ro_prefix6.b[0] == 0) return -1;

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);

    bool is_icmpx_error = xdp_nat6_is_icmp_error(view);
    bool allow_create = nat6_allows_create_pkt(proto, view->tcp_phase, is_icmpx_error);
    bool need_prefix_replace = false;
    int map_ret = 0;

    struct nat6_timer_value *ct_value = xdp_lookup_ct6_ingress(view, dst_addr, npt_id_mask);
    if (ct_value) {
        bool ct_is_static = ct_value->is_static != 0;
        *out_is_static = ct_is_static;

        if (!ct_is_static) {
            if (ct_value->is_allow_reuse == 0 && proto != NEXTHDR_ICMP) {
                if (!ip_addr_equal_x(src_addr, &ct_value->trigger_addr) ||
                    view->sport != ct_value->trigger_port) {
                    return -1;
                }
            }
        }

        COPY_ADDR_FROM(&local_client_prefix, ct_value->client_prefix);
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);

        __be64 dst_prefix;
        __builtin_memcpy(&dst_prefix, dst_addr->in6_u.u6_addr32, 8);
        if (!ct_value->need_prefix_replace || local_client_prefix == dst_prefix) {
            return ct_is_static ? 1 : 0;
        }
        need_prefix_replace = true;
        goto do_xdp_ingress_nptv6;
    }

    map_ret = nat6_check_ingress_static(proto, dst_addr, view->dport, &local_client_prefix);
    bool is_static = (map_ret != NAT6_STATIC_MISS);
    need_prefix_replace = (map_ret == NAT6_STATIC_REPLACE);
    *out_is_static = is_static;

    __be64 client_prefix_hint = 0;
    if (map_ret == NAT6_STATIC_REPLACE) {
        client_prefix_hint = local_client_prefix;
    } else if (map_ret == NAT6_STATIC_PASS) {
        COPY_ADDR_FROM(&client_prefix_hint, dst_addr->in6_u.u6_addr8);
    }

    if (!allow_create) {
        if (!is_static) return -1;
        goto do_xdp_ingress_nptv6;
    }

    if (!is_static) return -1;

    ct_value = xdp_create_ct6_ingress(wan_if, mark, view, src_addr, dst_addr, npt_id_mask,
                                      &client_prefix_hint, need_prefix_replace);
    if (ct_value) {
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);
    }

do_xdp_ingress_nptv6:
    if (map_ret == NAT6_STATIC_PASS) {
        return 1;
    }

    if (!need_prefix_replace) return 2;

    if (is_icmpx_error) {
        u32 inner_src_off = xdp_nat6_icmp_error_l3_offset(view) + offsetof(struct ipv6hdr, saddr);
        __be64 old_inner_ip_prefix;
        if (bpf_xdp_load_bytes(ctx, inner_src_off, &old_inner_ip_prefix,
                               sizeof(old_inner_ip_prefix)))
            return -1;

        u32 inner_l4_csum_off = 0;
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(view->icmp_inner_l4_offset, view->icmp_inner_l4_protocol,
                             &inner_l4_csum_off))
            return -1;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_csum_off)) return -1;

        __be16 old_inner_l4_csum;
        if (bpf_xdp_load_bytes(ctx, inner_l4_csum_off, &old_inner_l4_csum,
                               sizeof(old_inner_l4_csum)))
            return -1;

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_inner_ip_prefix, 8, (__u32 *)&local_client_prefix, 8, 0);
        __be16 new_inner_l4_csum = xdp_csum_apply(old_inner_l4_csum, addr_delta);

        __be16 outer_csum;
        if (bpf_xdp_load_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
        outer_csum = xdp_csum_apply(outer_csum, addr_delta);

        if (bpf_xdp_store_bytes(ctx, inner_l4_csum_off, &new_inner_l4_csum,
                                sizeof(new_inner_l4_csum)))
            return -1;
        if (bpf_xdp_store_bytes(ctx, inner_src_off, &local_client_prefix,
                                sizeof(local_client_prefix)))
            return -1;

        __be32 old_ic32 = (__be32)old_inner_l4_csum;
        __be32 new_ic32 = (__be32)new_inner_l4_csum;
        __wsum ic_delta = bpf_csum_diff(&old_ic32, 4, &new_ic32, 4, 0);
        outer_csum = xdp_csum_apply(outer_csum, ic_delta);

        u32 dst_ip_off = l3_offset + offsetof(struct ipv6hdr, daddr);
        if (bpf_xdp_store_bytes(ctx, dst_ip_off, &local_client_prefix, sizeof(local_client_prefix)))
            return -1;

        outer_csum = xdp_csum_apply(outer_csum, addr_delta);
        if (bpf_xdp_store_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
    } else {
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_csum_off)) return -1;

        u32 dst_ip_off = l3_offset + offsetof(struct ipv6hdr, daddr);
        void *dst_ptr = data + dst_ip_off;
        if (dst_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, dst_addr->in6_u.u6_addr32, 8);

        __builtin_memcpy(dst_ptr, &local_client_prefix, 8);

        __be16 *csum_ptr = data + l4_csum_off;
        if ((void *)(csum_ptr + 1) > data_end) return -1;
        __wsum delta =
            bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&local_client_prefix, 8, 0);
        *csum_ptr = xdp_csum_apply(*csum_ptr, delta);
    }

    return 0;
}

#endif /* __LD_XDP_NAT6_H__ */
