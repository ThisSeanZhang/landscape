#ifndef __LD_XDP_NAT6_H__
#define __LD_XDP_NAT6_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "nat_common.h"
#include "nat6_map_ops.h"
#include "nat6_ct_timer.h"
#include "../land_wan_ip.h"
#include "../fragment/xdp_frag6.h"
#include "xdp_csum_helpers.h"

#define LAND_IPV6_NET_PREFIX_TRANS_MASK (0x0FULL << 56)

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

static __always_inline int xdp_update_ipv6_cache_value(u32 mark, struct inet_pair *ip_pair,
                                                       struct nat6_timer_value *value) {
    COPY_ADDR_FROM(value->client_prefix, ip_pair->src_addr.bits);
    if (!value->is_static) {
        bool is_ancestor = ip_addr_equal_x(&ip_pair->dst_addr, &value->trigger_addr) &&
                           ip_pair->dst_port == value->trigger_port;
        if (is_ancestor) {
            bool allow_reuse_port = get_flow_allow_reuse_port(mark);
            value->is_allow_reuse = allow_reuse_port ? 1 : 0;
        }
    }
    value->flow_id = get_flow_id(mark);
    return 0;
}

static __always_inline struct nat6_timer_value *
xdp_lookup_ct6_ingress(u8 l4_protocol, struct inet_pair *ip_pair, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    return bpf_map_lookup_elem(&nat6_timer_map, &key);
}

static __always_inline struct nat6_timer_value *
xdp_create_ct6_ingress(u32 wan_if, u32 mark, u8 l4_protocol, struct inet_pair *ip_pair,
                       u8 npt_id_mask, const __be64 *client_prefix_hint, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(mark);
    new_value.gress = NAT_MAPPING_INGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = wan_if;
    COPY_ADDR_FROM(new_value.trigger_addr.bytes, ip_pair->src_addr.all);
    new_value.trigger_port = ip_pair->src_port;
    COPY_ADDR_FROM(new_value.client_prefix, client_prefix_hint);
    new_value.is_allow_reuse = 1;
    new_value.is_static = 1;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline struct nat6_timer_value *
xdp_lookup_ct6_egress(u32 mark, u8 l4_protocol, struct inet_pair *ip_pair, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (value) {
        if (!nat6_is_same_prefix(value->client_prefix, &ip_pair->src_addr, npt_id_mask)) {
            xdp_update_ipv6_cache_value(mark, ip_pair, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat6_timer_value *
xdp_create_ct6_egress(u32 wan_if, u32 mark, u8 l4_protocol, struct inet_pair *ip_pair,
                      u8 npt_id_mask, u8 is_allow_reuse, bool is_static, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(mark);
    new_value.gress = NAT_MAPPING_EGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = wan_if;
    COPY_ADDR_FROM(new_value.client_prefix, ip_pair->src_addr.bits);
    new_value.is_allow_reuse = is_allow_reuse;
    new_value.is_static = is_static ? 1 : 0;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;
    COPY_ADDR_FROM(new_value.trigger_addr.all, ip_pair->dst_addr.all);
    new_value.trigger_port = ip_pair->dst_port;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline int xdp_read_nat_info6(void *data, void *data_end,
                                              const struct scan_ipv6_idx *idx,
                                              struct inet_pair *pair) {
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);
    if ((void *)(ip6h + 1) > data_end) return -1;

    __builtin_memcpy(&pair->src_addr, &ip6h->saddr, sizeof(pair->src_addr));
    __builtin_memcpy(&pair->dst_addr, &ip6h->daddr, sizeof(pair->dst_addr));

    if (idx->icmp_error_l3_offset > 0) {
        struct ipv6hdr *inner_ip6 = data + idx->icmp_error_l3_offset;
        if ((void *)(inner_ip6 + 1) > data_end) return -1;
        __builtin_memcpy(&pair->src_addr, &inner_ip6->daddr, sizeof(pair->src_addr));
    }

    if (idx->fragment_type >= FRAG_MIDDLE) return 0;

    u8 l4_protocol = idx->l4_protocol;
    u16 l4_offset = idx->l4_offset;

    if (idx->icmp_error_l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->dst_port = tcph->source;
        pair->src_port = tcph->dest;
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = data + l4_offset;
        if ((void *)(tcph + 1) > data_end) return -1;
        pair->src_port = tcph->source;
        pair->dst_port = tcph->dest;
    } else if (idx->icmp_error_l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + idx->icmp_error_inner_l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->dst_port = udph->source;
        pair->src_port = udph->dest;
    } else if (l4_protocol == IPPROTO_UDP) {
        struct udphdr *udph = data + l4_offset;
        if ((void *)(udph + 1) > data_end) return -1;
        pair->src_port = udph->source;
        pair->dst_port = udph->dest;
    } else if (l4_protocol == IPPROTO_ICMP || l4_protocol == IPPROTO_ICMPV6) {
        u32 offset = l4_offset;
        if (idx->icmp_error_inner_l4_offset > 0) {
            offset = idx->icmp_error_inner_l4_offset;
        }
        struct icmp6hdr *icmp6h = data + offset;
        if ((void *)(icmp6h + 1) > data_end) return -1;
        pair->src_port = pair->dst_port = icmp6h->icmp6_dataun.u_echo.identifier;
    }

    return 0;
}

static __always_inline int xdp_ipv6_egress_prefix_check_and_replace(void *data, void *data_end,
                                                                    u32 wan_if, u32 mark,
                                                                    struct scan_ipv6_idx *idx,
                                                                    struct inet_pair *ip_pair) {
    struct wan_ip_info_key wan_key = {0};
    wan_key.ifindex = wan_if;
    wan_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    struct wan_ip_info_value *wan_ip = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_ip) return -1;

    u8 npt_id_mask = (u8)(wan_ip->npt_mask >> 56);

    bool is_icmpx_error = idx->icmp_error_l3_offset != 0 && idx->icmp_error_inner_l4_offset != 0;

    struct nat6_timer_value *ct_value =
        xdp_lookup_ct6_egress(mark, idx->l4_protocol, ip_pair, npt_id_mask);
    if (ct_value) {
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, false, ct_value);
        if (!ct_value->need_prefix_replace) return 0;
        goto do_xdp_nptv6;
    }

    struct static_nat6_mapping_value *static_val =
        nat6_check_egress_static(idx->l4_protocol, ip_pair);

    bool allow_create = !is_icmpx_error && pkt_can_begin_ct(idx->pkt_type);

    if (!allow_create) {
        if (!static_val) return -1;
        if (!nat6_static_needs_prefix_replace(static_val)) return 0;
        goto do_xdp_nptv6;
    }

    bool need_prefix_replace = static_val ? nat6_static_needs_prefix_replace(static_val) : true;
    u8 reuse = static_val ? 1 : (get_flow_allow_reuse_port(mark) ? 1 : 0);
    ct_value = xdp_create_ct6_egress(wan_if, mark, idx->l4_protocol, ip_pair, npt_id_mask, reuse,
                                     static_val != NULL, need_prefix_replace);
    if (!ct_value) return -1;
    nat6_ct_advance(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
    xdp_nat6_metric_accumulate(data, data_end, false, ct_value);
    if (!need_prefix_replace) return 0;

do_xdp_nptv6:
    if (is_icmpx_error) {
        u32 err_sender_off = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr);
        void *sender_ptr = data + err_sender_off;
        if (sender_ptr + 8 > data_end) return -1;
        __be64 old_sender_prefix;
        __builtin_memcpy(&old_sender_prefix, sender_ptr, 8);

        u32 inner_dst_off = idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, daddr);
        u32 inner_l4_csum_off = 0;
        if (nat6_l4_checksum(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                             &inner_l4_csum_off))
            return -1;
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, ip_pair->src_addr.all, 8);

        __be64 new_ip_prefix;
        __builtin_memcpy(&new_ip_prefix, wan_ip->addr.all, 8);
        new_ip_prefix = (old_ip_prefix & wan_ip->npt_mask) | (new_ip_prefix & ~wan_ip->npt_mask);

        __be64 new_sender_prefix;
        __builtin_memcpy(&new_sender_prefix, wan_ip->addr.all, 8);
        new_sender_prefix =
            (old_sender_prefix & wan_ip->npt_mask) | (new_sender_prefix & ~wan_ip->npt_mask);

        __be16 *inner_csum_ptr = data + inner_l4_csum_off;
        if ((void *)(inner_csum_ptr + 1) > data_end) return -1;
        __be16 old_inner_l4_csum = *inner_csum_ptr;

        void *inner_dst = data + inner_dst_off;
        if (inner_dst + 8 > data_end) return -1;
        __builtin_memcpy(inner_dst, &new_ip_prefix, 8);

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);
        *inner_csum_ptr = xdp_csum_apply(*inner_csum_ptr, addr_delta);

        __be16 *outer_csum_ptr = data + l4_csum_off;
        if ((void *)(outer_csum_ptr + 1) > data_end) return -1;
        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, addr_delta);

        __be16 new_inner_l4_csum = *inner_csum_ptr;
        __be32 old_ic32 = (__be32)old_inner_l4_csum;
        __be32 new_ic32 = (__be32)new_inner_l4_csum;
        __wsum ic_delta = bpf_csum_diff(&old_ic32, 4, &new_ic32, 4, 0);
        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, ic_delta);

        __builtin_memcpy(sender_ptr, &new_sender_prefix, 8);
        __wsum sender_delta =
            bpf_csum_diff((__u32 *)&old_sender_prefix, 8, (__u32 *)&new_sender_prefix, 8, 0);
        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, sender_delta);

    } else {
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

        u32 ip_src_off = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr);
        void *src_ptr = data + ip_src_off;
        if (src_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, ip_pair->src_addr.all, 8);

        __be64 new_ip_prefix;
        __builtin_memcpy(&new_ip_prefix, wan_ip->addr.all, 8);
        new_ip_prefix = (old_ip_prefix & wan_ip->npt_mask) | (new_ip_prefix & ~wan_ip->npt_mask);

        __builtin_memcpy(src_ptr, &new_ip_prefix, 8);

        __be16 *csum_ptr = data + l4_csum_off;
        if ((void *)(csum_ptr + 1) > data_end) return -1;
        __wsum delta = bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);
        *csum_ptr = xdp_csum_apply(*csum_ptr, delta);
    }

    return 0;
}

static __always_inline int xdp_ipv6_ingress_prefix_check_and_replace(void *data, void *data_end,
                                                                     u32 wan_if, u32 mark,
                                                                     struct scan_ipv6_idx *idx,
                                                                     struct inet_pair *ip_pair,
                                                                     bool *out_is_static) {
    __be64 local_client_prefix = {0};

    struct wan_ip_info_key wan_key = {0};
    wan_key.ifindex = wan_if;
    wan_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    struct wan_ip_info_value *wan_ip = bpf_map_lookup_elem(&wan_ip_binding, &wan_key);
    if (!wan_ip) return -1;

    u8 npt_id_mask = (u8)(wan_ip->npt_mask >> 56);

    bool is_icmpx_error = idx->icmp_error_l3_offset != 0 && idx->icmp_error_inner_l4_offset != 0;
    bool allow_create = !is_icmpx_error && pkt_can_begin_ct(idx->pkt_type);
    bool need_prefix_replace = false;
    int map_ret = 0;

    struct nat6_timer_value *ct_value =
        xdp_lookup_ct6_ingress(idx->l4_protocol, ip_pair, npt_id_mask);
    if (ct_value) {
        bool ct_is_static = ct_value->is_static != 0;
        *out_is_static = ct_is_static;

        if (!ct_is_static) {
            if (ct_value->is_allow_reuse == 0 && idx->l4_protocol != IPPROTO_ICMPV6) {
                if (!ip_addr_equal_x(&ip_pair->src_addr, &ct_value->trigger_addr) ||
                    ip_pair->src_port != ct_value->trigger_port) {
                    return -1;
                }
            }
        }

        COPY_ADDR_FROM(&local_client_prefix, ct_value->client_prefix);
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);

        __be64 dst_prefix;
        __builtin_memcpy(&dst_prefix, ip_pair->dst_addr.all, 8);
        if (!ct_value->need_prefix_replace || local_client_prefix == dst_prefix) {
            return ct_is_static ? 1 : 0;
        }
        need_prefix_replace = true;
        goto do_xdp_ingress_nptv6;
    }

    map_ret = nat6_check_ingress_static(idx->l4_protocol, ip_pair, &local_client_prefix);
    bool is_static = (map_ret != NAT6_STATIC_MISS);
    need_prefix_replace = (map_ret == NAT6_STATIC_REPLACE);
    *out_is_static = is_static;

    __be64 client_prefix_hint = 0;
    if (map_ret == NAT6_STATIC_REPLACE) {
        client_prefix_hint = local_client_prefix;
    } else if (map_ret == NAT6_STATIC_PASS) {
        COPY_ADDR_FROM(&client_prefix_hint, ip_pair->dst_addr.bits);
    }

    if (!allow_create) {
        if (!is_static) return -1;
        goto do_xdp_ingress_nptv6;
    }

    if (!is_static) return -1;

    ct_value = xdp_create_ct6_ingress(wan_if, mark, idx->l4_protocol, ip_pair, npt_id_mask,
                                      &client_prefix_hint, need_prefix_replace);
    if (ct_value) {
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);
    }

do_xdp_ingress_nptv6:
    if (map_ret == NAT6_STATIC_PASS) {
        return 1;
    }

    if (!need_prefix_replace) return 2;

    if (is_icmpx_error) {
        u32 inner_src_off = idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr);
        void *inner_src_ptr = data + inner_src_off;
        if (inner_src_ptr + 8 > data_end) return -1;
        __be64 old_inner_ip_prefix;
        __builtin_memcpy(&old_inner_ip_prefix, inner_src_ptr, 8);

        u32 inner_l4_csum_off = 0;
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                             &inner_l4_csum_off))
            return -1;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

        __be16 *inner_csum_ptr = data + inner_l4_csum_off;
        if ((void *)(inner_csum_ptr + 1) > data_end) return -1;
        __be16 old_inner_l4_csum = *inner_csum_ptr;

        __builtin_memcpy(inner_src_ptr, &local_client_prefix, 8);

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_inner_ip_prefix, 8, (__u32 *)&local_client_prefix, 8, 0);
        *inner_csum_ptr = xdp_csum_apply(*inner_csum_ptr, addr_delta);

        __be16 *outer_csum_ptr = data + l4_csum_off;
        if ((void *)(outer_csum_ptr + 1) > data_end) return -1;
        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, addr_delta);

        __be16 new_inner_l4_csum = *inner_csum_ptr;
        __be32 old_ic32 = (__be32)old_inner_l4_csum;
        __be32 new_ic32 = (__be32)new_inner_l4_csum;
        __wsum ic_delta = bpf_csum_diff(&old_ic32, 4, &new_ic32, 4, 0);
        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, ic_delta);

        u32 dst_ip_off = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr);
        void *dst_ptr = data + dst_ip_off;
        if (dst_ptr + 8 > data_end) return -1;
        __builtin_memcpy(dst_ptr, &local_client_prefix, 8);

        *outer_csum_ptr = xdp_csum_apply(*outer_csum_ptr, addr_delta);

    } else {
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

        u32 dst_ip_off = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr);
        void *dst_ptr = data + dst_ip_off;
        if (dst_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, ip_pair->dst_addr.all, 8);

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
