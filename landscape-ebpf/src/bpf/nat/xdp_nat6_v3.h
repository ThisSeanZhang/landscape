#ifndef __LD_XDP_NAT6_V3_H__
#define __LD_XDP_NAT6_V3_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../land_nat_common.h"
#include "../land_wan_ip.h"
#include "nat_maps.h"
#include "xdp_csum_helpers.h"

#define LAND_IPV6_NET_PREFIX_TRANS_MASK (0x0FULL << 56)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct nat_timer_key_v6);
    __type(value, struct nat_timer_value_v6);
    __uint(max_entries, NAT_MAPPING_TIMER_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} nat6_conn_timer SEC(".maps");

static __always_inline int xdp_get_l4_checksum_offset(u32 l4_offset, u8 l4_protocol,
                                                      u32 *l4_checksum_offset) {
    if (l4_protocol == IPPROTO_TCP) {
        *l4_checksum_offset = l4_offset + offsetof(struct tcphdr, check);
    } else if (l4_protocol == IPPROTO_UDP) {
        *l4_checksum_offset = l4_offset + offsetof(struct udphdr, check);
    } else if (l4_protocol == IPPROTO_ICMPV6) {
        *l4_checksum_offset = l4_offset + offsetof(struct icmp6hdr, icmp6_cksum);
    } else {
        return -1;
    }
    return 0;
}

static __always_inline bool xdp_is_same_prefix(const u8 prefix[8], const union u_inet_addr *a,
                                               u8 npt_id_mask) {
    const u8 *b = a->bits;
    u8 prefix_mask = (u8)~npt_id_mask;
    return prefix[0] == b[0] && prefix[1] == b[1] && prefix[2] == b[2] && prefix[3] == b[3] &&
           prefix[4] == b[4] && prefix[5] == b[5] && prefix[6] == b[6] &&
           ((prefix[7] & prefix_mask) == (b[7] & prefix_mask));
}

static __always_inline void xdp_nat6_metric_accumulate(void *data, void *data_end, bool ingress,
                                                       struct nat_timer_value_v6 *value) {
    u64 bytes = (u64)(long)data_end - (u64)(long)data;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline bool xdp_ct6_change_state(u64 *status_in_value, u64 curr_state,
                                                 u64 next_state) {
    return __sync_bool_compare_and_swap(status_in_value, curr_state, next_state);
}

static __always_inline int xdp_ct6_state_transition(u8 pkt_type, u8 gress,
                                                    struct nat_timer_value_v6 *ct_timer_value) {
    u64 curr_state, *modify_status = NULL;
    if (gress == NAT_MAPPING_INGRESS) {
        curr_state = ct_timer_value->server_status;
        modify_status = &ct_timer_value->server_status;
    } else {
        curr_state = ct_timer_value->client_status;
        modify_status = &ct_timer_value->client_status;
    }

#define NEW_STATE_V6(__state)                                                                      \
    if (!xdp_ct6_change_state(modify_status, curr_state, (__state))) {                             \
        return -1;                                                                                 \
    }

    if (pkt_type == PKT_CONNLESS_V2) {
        NEW_STATE_V6(CT_LESS_EST);
    }
    if (pkt_type == PKT_TCP_RST_V2) {
        NEW_STATE_V6(CT_INIT);
    }
    if (pkt_type == PKT_TCP_SYN_V2) {
        NEW_STATE_V6(CT_SYN);
    }
    if (pkt_type == PKT_TCP_FIN_V2) {
        NEW_STATE_V6(CT_FIN);
    }

#undef NEW_STATE_V6

    u64 prev_state = __sync_lock_test_and_set(&ct_timer_value->status, TIMER_ACTIVE);
    if (prev_state != TIMER_ACTIVE) {
        bpf_timer_start(&ct_timer_value->timer, REPORT_INTERVAL, 0);
    }
    return 0;
}

static int xdp_v6_timer_clean_callback(void *map_, struct nat_timer_key_v6 *key,
                                       struct nat_timer_value_v6 *value) {
    u64 client_status = value->client_status;
    u64 server_status = value->server_status;
    u64 current_status = value->status;
    u64 next_status = current_status;
    u64 next_timeout = REPORT_INTERVAL;

    if (current_status == TIMER_RELEASE) {
        goto release;
    }

    if (current_status == TIMER_ACTIVE) {
        next_status = TIMER_TIMEOUT_1;
        next_timeout = REPORT_INTERVAL;
    } else if (current_status == TIMER_TIMEOUT_1) {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;
    } else if (current_status == TIMER_TIMEOUT_2) {
        next_status = TIMER_RELEASE;
        if (key->l4_protocol == IPPROTO_TCP) {
            next_timeout = (client_status == CT_SYN && server_status == CT_SYN) ? TCP_TIMEOUT
                                                                                : TCP_SYN_TIMEOUT;
        } else {
            next_timeout = UDP_TIMEOUT;
        }
    } else {
        next_status = TIMER_TIMEOUT_2;
        next_timeout = REPORT_INTERVAL;
    }

    if (__sync_val_compare_and_swap(&value->status, current_status, next_status) !=
        current_status) {
        bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
        return 0;
    }
    bpf_timer_start(&value->timer, next_timeout, 0);
    return 0;

release:
    bpf_map_delete_elem(&nat6_conn_timer, key);
    return 0;
}

static __always_inline struct nat_timer_value_v6 *
xdp_insert_ct6_timer(const struct nat_timer_key_v6 *key, struct nat_timer_value_v6 *val) {
    int ret = bpf_map_update_elem(&nat6_conn_timer, key, val, BPF_NOEXIST);
    if (ret) return NULL;
    struct nat_timer_value_v6 *value = bpf_map_lookup_elem(&nat6_conn_timer, key);
    if (!value) return NULL;

    ret = bpf_timer_init(&value->timer, &nat6_conn_timer, CLOCK_MONOTONIC);
    if (ret) goto delete_timer;
    ret = bpf_timer_set_callback(&value->timer, xdp_v6_timer_clean_callback);
    if (ret) goto delete_timer;
    ret = bpf_timer_start(&value->timer, REPORT_INTERVAL, 0);
    if (ret) goto delete_timer;
    return value;

delete_timer:
    bpf_map_delete_elem(&nat6_conn_timer, key);
    return NULL;
}

static __always_inline int xdp_update_ipv6_cache_value(u32 mark, struct inet_pair *ip_pair,
                                                       struct nat_timer_value_v6 *value) {
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

static __always_inline struct static_nat_mapping_value_v6 *
xdp_check_egress_static_mapping(u8 ip_protocol, const struct inet_pair *pkt_ip_pair) {
    struct static_nat_mapping_key_v6 egress_key = {0};
    egress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    egress_key.l4_protocol = ip_protocol;
    egress_key.gress = NAT_MAPPING_EGRESS;
    egress_key.prefixlen = 192;
    egress_key.port = pkt_ip_pair->src_port;
    COPY_ADDR_FROM(egress_key.addr.all, pkt_ip_pair->src_addr.all);
    return bpf_map_lookup_elem(&nat6_static_mappings, &egress_key);
}

static __always_inline int xdp_check_ingress_mapping(u8 ip_protocol,
                                                     const struct inet_pair *pkt_ip_pair,
                                                     __be64 *local_client_prefix) {
    struct static_nat_mapping_key_v6 ingress_key = {0};
    ingress_key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    ingress_key.l4_protocol = ip_protocol;
    ingress_key.gress = NAT_MAPPING_INGRESS;
    ingress_key.prefixlen = 96;
    ingress_key.port = pkt_ip_pair->dst_port;

    struct static_nat_mapping_value_v6 *value =
        bpf_map_lookup_elem(&nat6_static_mappings, &ingress_key);
    if (value) {
        if (value->addr.all[3] == 0 && value->addr.all[2] == 0) return -1;
        if (value->addr.ip != 0) {
            COPY_ADDR_FROM(local_client_prefix, value->addr.bytes);
            return 0;
        }
        __be64 mapping_suffix, dst_suffix;
        COPY_ADDR_FROM(&mapping_suffix, value->addr.bytes + 8);
        COPY_ADDR_FROM(&dst_suffix, pkt_ip_pair->dst_addr.bits + 8);
        if (mapping_suffix == dst_suffix) return -1;
    }
    return -2;
}

static __always_inline struct nat_timer_value_v6 *
xdp_lookup_ct6_ingress(u8 l4_protocol, struct inet_pair *ip_pair, u8 npt_id_mask) {
    struct nat_timer_key_v6 key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    return bpf_map_lookup_elem(&nat6_conn_timer, &key);
}

static __always_inline struct nat_timer_value_v6 *
xdp_create_ct6_ingress(u32 wan_if, u32 mark, u8 l4_protocol, struct inet_pair *ip_pair,
                       u8 npt_id_mask, const __be64 *client_prefix_hint) {
    struct nat_timer_key_v6 key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat_timer_value_v6 new_value = {};
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

    return xdp_insert_ct6_timer(&key, &new_value);
}

static __always_inline struct nat_timer_value_v6 *
xdp_lookup_ct6_egress(u32 mark, u8 l4_protocol, struct inet_pair *ip_pair, u8 npt_id_mask) {
    struct nat_timer_key_v6 key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat_timer_value_v6 *value = bpf_map_lookup_elem(&nat6_conn_timer, &key);
    if (value) {
        if (!xdp_is_same_prefix(value->client_prefix, &ip_pair->src_addr, npt_id_mask)) {
            xdp_update_ipv6_cache_value(mark, ip_pair, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat_timer_value_v6 *
xdp_create_ct6_egress(u32 wan_if, u32 mark, u8 l4_protocol, struct inet_pair *ip_pair,
                      u8 npt_id_mask, u8 is_allow_reuse, bool is_static) {
    struct nat_timer_key_v6 key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = l4_protocol;

    struct nat_timer_value_v6 new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(mark);
    new_value.gress = NAT_MAPPING_EGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = wan_if;
    COPY_ADDR_FROM(new_value.client_prefix, ip_pair->src_addr.bits);
    new_value.is_allow_reuse = is_allow_reuse;
    new_value.is_static = is_static ? 1 : 0;
    COPY_ADDR_FROM(new_value.trigger_addr.all, ip_pair->dst_addr.all);
    new_value.trigger_port = ip_pair->dst_port;

    return xdp_insert_ct6_timer(&key, &new_value);
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

    struct nat_timer_value_v6 *ct_value =
        xdp_lookup_ct6_egress(mark, idx->l4_protocol, ip_pair, npt_id_mask);
    if (ct_value) {
        xdp_ct6_state_transition(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, false, ct_value);
        goto do_xdp_nptv6;
    }

    struct static_nat_mapping_value_v6 *static_val =
        xdp_check_egress_static_mapping(idx->l4_protocol, ip_pair);

    bool is_icmpx_error = idx->icmp_error_l3_offset != 0 && idx->icmp_error_inner_l4_offset != 0;
    bool allow_create = !is_icmpx_error && pkt_allow_initiating_ct(idx->pkt_type);

    if (!allow_create) {
        if (!static_val) return -1;
        goto do_xdp_nptv6;
    }

    u8 reuse = static_val ? static_val->is_allow_reuse : (get_flow_allow_reuse_port(mark) ? 1 : 0);
    ct_value = xdp_create_ct6_egress(wan_if, mark, idx->l4_protocol, ip_pair, npt_id_mask, reuse,
                                     static_val != NULL);
    if (!ct_value) return -1;
    xdp_ct6_state_transition(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
    xdp_nat6_metric_accumulate(data, data_end, false, ct_value);

do_xdp_nptv6:
    if (is_icmpx_error) {
        u32 err_sender_off = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr);
        void *sender_ptr = data + err_sender_off;
        if (sender_ptr + 8 > data_end) return -1;
        __be64 old_sender_prefix;
        __builtin_memcpy(&old_sender_prefix, sender_ptr, 8);

        u32 inner_dst_off = idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, daddr);
        u32 inner_l4_csum_off = 0;
        if (xdp_get_l4_checksum_offset(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                                       &inner_l4_csum_off))
            return -1;
        u32 l4_csum_off = 0;
        if (xdp_get_l4_checksum_offset(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

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
        if (xdp_get_l4_checksum_offset(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

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
    bool allow_create = !is_icmpx_error && pkt_allow_initiating_ct(idx->pkt_type);
    bool need_prefix_replace = false;
    int map_ret = 0;

    struct nat_timer_value_v6 *ct_value =
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
        xdp_ct6_state_transition(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);

        __be64 dst_prefix;
        __builtin_memcpy(&dst_prefix, ip_pair->dst_addr.all, 8);
        if (local_client_prefix == dst_prefix) {
            return ct_is_static ? 1 : 0;
        }
        need_prefix_replace = true;
        goto do_xdp_ingress_nptv6;
    }

    map_ret = xdp_check_ingress_mapping(idx->l4_protocol, ip_pair, &local_client_prefix);
    bool is_static = (map_ret != -2);
    need_prefix_replace = (map_ret == 0);
    *out_is_static = is_static;

    __be64 client_prefix_hint = 0;
    if (map_ret == 0) {
        client_prefix_hint = local_client_prefix;
    } else if (map_ret == -1) {
        COPY_ADDR_FROM(&client_prefix_hint, ip_pair->dst_addr.bits);
    }

    if (!allow_create) {
        if (!is_static) return -1;
        goto do_xdp_ingress_nptv6;
    }

    if (!is_static) return -1;

    ct_value = xdp_create_ct6_ingress(wan_if, mark, idx->l4_protocol, ip_pair, npt_id_mask,
                                      &client_prefix_hint);
    if (ct_value) {
        xdp_ct6_state_transition(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        xdp_nat6_metric_accumulate(data, data_end, true, ct_value);
    }

do_xdp_ingress_nptv6:
    if (map_ret == -1) {
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
        if (xdp_get_l4_checksum_offset(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                                       &inner_l4_csum_off))
            return -1;
        if (xdp_get_l4_checksum_offset(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

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
        if (xdp_get_l4_checksum_offset(idx->l4_offset, idx->l4_protocol, &l4_csum_off)) return -1;

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

#endif /* __LD_XDP_NAT6_V3_H__ */
