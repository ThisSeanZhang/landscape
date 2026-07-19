#ifndef LD_NAT6_V3_H
#define LD_NAT6_V3_H
#include <vmlinux.h>
#include "../landscape_log.h"
#include "../scanner/scan_types.h"
#include "nat_common.h"
#include "nat6_map_ops.h"
#include "nat6_ct_timer.h"
#include "../land_wan_ip.h"

#define LAND_IPV6_NET_PREFIX_TRANS_MASK (0x0FULL << 56)

static __always_inline int update_ipv6_cache_value(struct __sk_buff *skb, struct inet_pair *ip_pair,
                                                   struct nat6_timer_value *value) {
    COPY_ADDR_FROM(value->client_prefix, ip_pair->src_addr.bits);
    if (!value->is_static) {
        bool is_ancestor = ip_addr_equal_x(&ip_pair->dst_addr, &value->trigger_addr) &&
                           ip_pair->dst_port == value->trigger_port;
        if (is_ancestor) {
            bool allow_reuse_port = get_flow_allow_reuse_port(skb->mark);
            value->is_allow_reuse = allow_reuse_port ? 1 : 0;
        }
    }
    value->flow_id = get_flow_id(skb->mark);
    return 0;
}

static __always_inline void nat6_metric_accumulate(struct __sk_buff *skb, bool ingress,
                                                   struct nat6_timer_value *value) {
    u64 bytes = skb->len;
    if (ingress) {
        __sync_fetch_and_add(&value->ingress_bytes, bytes);
        __sync_fetch_and_add(&value->ingress_packets, 1);
    } else {
        __sync_fetch_and_add(&value->egress_bytes, bytes);
        __sync_fetch_and_add(&value->egress_packets, 1);
    }
}

static __always_inline struct nat6_timer_value *lookup_ct6_egress(struct __sk_buff *skb,
                                                                  struct scan_ipv6_idx *idx,
                                                                  struct inet_pair *ip_pair,
                                                                  u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = idx->l4_protocol;

    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (value) {
        if (!nat6_is_same_prefix(value->client_prefix, &ip_pair->src_addr, npt_id_mask)) {
            update_ipv6_cache_value(skb, ip_pair, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat6_timer_value *
create_ct6_egress(struct __sk_buff *skb, struct scan_ipv6_idx *idx, struct inet_pair *ip_pair,
                  u8 npt_id_mask, u32 ifindex, u8 is_allow_reuse, bool is_static,
                  bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->src_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->src_addr.bits + 8);
    key.id_byte = ip_pair->src_addr.bits[7] & npt_id_mask;
    key.l4_protocol = idx->l4_protocol;

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.gress = NAT_MAPPING_EGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    COPY_ADDR_FROM(new_value.client_prefix, ip_pair->src_addr.bits);
    new_value.is_allow_reuse = is_allow_reuse;
    new_value.is_static = is_static ? 1 : 0;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;
    COPY_ADDR_FROM(new_value.trigger_addr.all, ip_pair->dst_addr.all);
    new_value.trigger_port = ip_pair->dst_port;

    return nat6_insert_timer(&key, &new_value);
}

#define L4_CSUM_REPLACE_U64_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, flags)                 \
    do {                                                                                           \
        int _ret;                                                                                  \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) >> 32, (new_val) >> 32,         \
                                   flags | 4);                                                     \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace high 32bit err: %d", _ret);                                \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) & 0xFFFFFFFF,                   \
                                   (new_val) & 0xFFFFFFFF, flags | 4);                             \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace low 32bit err: %d", _ret);                                 \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int ipv6_egress_prefix_check_and_replace(struct __sk_buff *skb,
                                                                struct scan_ipv6_idx *idx,
                                                                struct inet_pair *ip_pair,
                                                                u32 l3_offset, u32 ifindex) {
#define BPF_LOG_TOPIC "ipv6_egress_prefix_check_and_replace"
    int ret;

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (wan_ip_info == NULL) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ip_info->npt_mask >> 56);

    struct nat6_timer_value *ct_value = lookup_ct6_egress(skb, idx, ip_pair, npt_id_mask);
    if (ct_value) {
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
        nat6_metric_accumulate(skb, false, ct_value);
        if (!ct_value->need_prefix_replace) {
            return TC_ACT_UNSPEC;
        }
        goto do_nptv6;
    }

    struct static_nat6_mapping_value *static_val =
        nat6_check_egress_static(idx->l4_protocol, ip_pair);

    bool is_icmpx_error = idx->icmp_error_l3_offset > 0 && idx->icmp_error_inner_l4_offset > 0;
    bool allow_create = !is_icmpx_error && pkt_can_begin_ct(idx->pkt_type);

    if (!allow_create) {
        if (!static_val) {
            return TC_ACT_SHOT;
        }
        if (!nat6_static_needs_prefix_replace(static_val)) {
            return TC_ACT_UNSPEC;
        }
        goto do_nptv6;
    }

    bool need_prefix_replace = static_val ? nat6_static_needs_prefix_replace(static_val) : true;
    u8 reuse = static_val ? 1 : (get_flow_allow_reuse_port(skb->mark) ? 1 : 0);
    ct_value = create_ct6_egress(skb, idx, ip_pair, npt_id_mask, ifindex, reuse, static_val != NULL,
                                 need_prefix_replace);
    if (!ct_value) {
        return TC_ACT_SHOT;
    }
    nat6_ct_advance(idx->pkt_type, NAT_MAPPING_EGRESS, ct_value);
    nat6_metric_accumulate(skb, false, ct_value);
    if (!need_prefix_replace) {
        return TC_ACT_UNSPEC;
    }

do_nptv6:
    if (idx->icmp_error_l3_offset > 0 && idx->icmp_error_inner_l4_offset > 0) {
        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix =
            (old_ip_prefix & wan_ip_info->npt_mask) | (new_ip_prefix & ~wan_ip_info->npt_mask);

        u32 error_sender_offset = l3_offset + offsetof(struct ipv6hdr, saddr);
        u32 inner_l3_ip_dst_offset = idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, daddr);

        __be64 old_sender_ip_prefix, new_sender_ip_prefix;
#if defined(LAND_ARCH_RISCV)
        if (bpf_skb_load_bytes(skb, error_sender_offset, &old_sender_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        __be64 *error_sender_point;
        if (VALIDATE_READ_DATA(skb, &error_sender_point, error_sender_offset,
                               sizeof(*error_sender_point))) {
            return TC_ACT_SHOT;
        }
        old_sender_ip_prefix = *error_sender_point;
#endif
        COPY_ADDR_FROM(&new_sender_ip_prefix, wan_ip_info->addr.all);

        new_sender_ip_prefix = (old_sender_ip_prefix & wan_ip_info->npt_mask) |
                               (new_sender_ip_prefix & ~wan_ip_info->npt_mask);

        u32 inner_l4_checksum_offset = 0;
        if (nat6_l4_checksum(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                             &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_dst_offset, &new_ip_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix, 0);

        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);

        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        bpf_skb_store_bytes(skb, error_sender_offset, &new_sender_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_sender_ip_prefix,
                                    new_sender_ip_prefix, BPF_F_PSEUDO_HDR);

    } else {
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 ip_src_offset = l3_offset + offsetof(struct ipv6hdr, saddr);

        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->src_addr.all);
        COPY_ADDR_FROM(&new_ip_prefix, wan_ip_info->addr.all);
        new_ip_prefix =
            (old_ip_prefix & wan_ip_info->npt_mask) | (new_ip_prefix & ~wan_ip_info->npt_mask);
        bpf_skb_store_bytes(skb, ip_src_offset, &new_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, new_ip_prefix,
                                    BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

static __always_inline struct nat6_timer_value *
lookup_ct6_ingress(struct scan_ipv6_idx *idx, struct inet_pair *ip_pair, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = idx->l4_protocol;

    return bpf_map_lookup_elem(&nat6_timer_map, &key);
}

static __always_inline struct nat6_timer_value *
create_ct6_ingress(struct __sk_buff *skb, struct scan_ipv6_idx *idx, struct inet_pair *ip_pair,
                   u8 npt_id_mask, u32 ifindex, const __be64 *client_prefix_hint,
                   bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = ip_pair->dst_port;
    COPY_ADDR_FROM(key.client_suffix, ip_pair->dst_addr.bits + 8);
    key.id_byte = ip_pair->dst_addr.bits[7] & npt_id_mask;
    key.l4_protocol = idx->l4_protocol;

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.gress = NAT_MAPPING_INGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    COPY_ADDR_FROM(new_value.trigger_addr.bytes, ip_pair->src_addr.all);
    new_value.trigger_port = ip_pair->src_port;
    COPY_ADDR_FROM(new_value.client_prefix, client_prefix_hint);
    new_value.is_allow_reuse = 1;
    new_value.is_static = 1;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline int ipv6_ingress_prefix_check_and_replace(struct __sk_buff *skb,
                                                                 struct scan_ipv6_idx *idx,
                                                                 struct inet_pair *ip_pair,
                                                                 u32 l3_offset, u32 ifindex) {
#define BPF_LOG_TOPIC "ipv6_ingress_prefix_check_and_replace"
    int ret = 0;
    __be64 local_client_prefix = {0};

    struct wan_ip_info_key wan_search_key = {0};
    wan_search_key.ifindex = ifindex;
    wan_search_key.l3_protocol = LANDSCAPE_IPV6_TYPE;

    struct wan_ip_info_value *wan_ip_info = bpf_map_lookup_elem(&wan_ip_binding, &wan_search_key);
    if (wan_ip_info == NULL) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ip_info->npt_mask >> 56);

    bool is_icmpx = idx->icmp_error_l3_offset > 0 && idx->icmp_error_inner_l4_offset > 0;
    bool allow_create = !is_icmpx && pkt_can_begin_ct(idx->pkt_type);
    bool need_prefix_replace = false;

    struct nat6_timer_value *ct_value = lookup_ct6_ingress(idx, ip_pair, npt_id_mask);
    if (ct_value) {
        bool ct_is_static = ct_value->is_static != 0;

        if (!ct_is_static) {
            if (ct_value->is_allow_reuse == 0 && idx->l4_protocol != IPPROTO_ICMPV6) {
                if (!ip_addr_equal_x(&ip_pair->src_addr, &ct_value->trigger_addr) ||
                    ip_pair->src_port != ct_value->trigger_port) {
                    bpf_printk("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                    bpf_printk("src info: [%pI6]:%u", &ip_pair->src_addr,
                               bpf_ntohs(ip_pair->src_port));
                    bpf_printk("trigger ip: [%pI6]:%u,", &ct_value->trigger_addr,
                               bpf_ntohs(ct_value->trigger_port));
                    return TC_ACT_SHOT;
                }
            }
        }

        COPY_ADDR_FROM(&local_client_prefix, ct_value->client_prefix);
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        nat6_metric_accumulate(skb, true, ct_value);

        __be64 dst_prefix;
        COPY_ADDR_FROM(&dst_prefix, ip_pair->dst_addr.bits);
        if (!ct_value->need_prefix_replace || local_client_prefix == dst_prefix) {
            if (ct_is_static) {
                u32 mark = skb->mark;
                barrier_var(mark);
                skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
            }
            return TC_ACT_UNSPEC;
        }
        need_prefix_replace = true;
        goto do_ingress_nptv6;
    }

    ret = nat6_check_ingress_static(idx->l4_protocol, ip_pair, &local_client_prefix);
    bool is_static = (ret != NAT6_STATIC_MISS);
    need_prefix_replace = (ret == NAT6_STATIC_REPLACE);

    __be64 client_prefix_hint = 0;
    if (ret == NAT6_STATIC_REPLACE) {
        client_prefix_hint = local_client_prefix;
    } else if (ret == NAT6_STATIC_PASS) {
        COPY_ADDR_FROM(&client_prefix_hint, ip_pair->dst_addr.bits);
    }

    if (!allow_create) {
        if (!is_static) return TC_ACT_SHOT;
        goto do_ingress_nptv6;
    }

    if (!is_static) {
        bpf_printk("ingress dynamic no CT, l4_proto: %u, dst_port: %04x", idx->l4_protocol,
                   ip_pair->dst_port);
        return TC_ACT_SHOT;
    }

    ct_value = create_ct6_ingress(skb, idx, ip_pair, npt_id_mask, ifindex, &client_prefix_hint,
                                  need_prefix_replace);
    if (ct_value) {
        nat6_ct_advance(idx->pkt_type, NAT_MAPPING_INGRESS, ct_value);
        nat6_metric_accumulate(skb, true, ct_value);
    }

do_ingress_nptv6:
    if (ret == NAT6_STATIC_PASS) {
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
        return TC_ACT_UNSPEC;
    }

    if (!need_prefix_replace) {
        return TC_ACT_UNSPEC;
    }

    if (is_icmpx) {
        u32 inner_l3_ip_src_offset = idx->icmp_error_l3_offset + offsetof(struct ipv6hdr, saddr);

        __be64 old_inner_ip_prefix;
#if defined(LAND_ARCH_RISCV)
        if (bpf_skb_load_bytes(skb, inner_l3_ip_src_offset, &old_inner_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        __be64 *old_inner_ip_point;
        if (VALIDATE_READ_DATA(skb, &old_inner_ip_point, inner_l3_ip_src_offset,
                               sizeof(*old_inner_ip_point))) {
            return TC_ACT_SHOT;
        }
        old_inner_ip_prefix = *old_inner_ip_point;
#endif

        u32 inner_l4_checksum_offset = 0;
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(idx->icmp_error_inner_l4_offset, idx->icmp_error_l4_protocol,
                             &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_src_offset, &local_client_prefix, 8, 0);
        if (ret) {
            bpf_printk("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, inner_l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);
        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            bpf_printk("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        u32 ipv6_dst_offset = l3_offset + offsetof(struct ipv6hdr, daddr);
        bpf_skb_store_bytes(skb, ipv6_dst_offset, &local_client_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, BPF_F_PSEUDO_HDR);
    } else {
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(idx->l4_offset, idx->l4_protocol, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 dst_ip_offset = l3_offset + offsetof(struct ipv6hdr, daddr);

        __be64 old_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, ip_pair->dst_addr.all);
        bpf_skb_store_bytes(skb, dst_ip_offset, &local_client_prefix, 8, 0);

        L4_CSUM_REPLACE_U64_OR_SHOT(skb, l4_checksum_offset, old_ip_prefix, local_client_prefix,
                                    BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
#undef BPF_LOG_TOPIC
}

#endif /* LD_NAT6_V3_H */
