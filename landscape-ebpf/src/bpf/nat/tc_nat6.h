#ifndef LD_NAT6_V3_H
#define LD_NAT6_V3_H
#include <vmlinux.h>
#include "base/printk.h"
#include "base/tcp_phase.h"
#include "reader/tc_nat_view.h"
#include "nat/nat_common.h"
#include "nat/nat6_map_ops.h"
#include "nat/nat6_ct_timer.h"
#include "nat/nat_rodata6.h"

static __always_inline __u8 nat6_outer_protocol(const struct tc_nat_view *view) {
    return view->icmp_inner_l4_offset ? NEXTHDR_ICMP : view->l4_protocol;
}

static __always_inline bool nat6_is_icmp_error(const struct tc_nat_view *view) {
    return view->icmp_inner_l4_offset != 0;
}

static __always_inline __u16 nat6_icmp_error_l3_offset(const struct tc_nat_view *view) {
    return view->icmp_inner_l4_offset ? (__u16)(view->l4_offset + sizeof(struct icmp6hdr)) : 0;
}

static __always_inline int update_ipv6_cache_value(struct __sk_buff *skb,
                                                   const struct tc_nat_view *view,
                                                   const struct in6_addr *src_addr,
                                                   const struct in6_addr *dst_addr,
                                                   struct nat6_timer_value *value) {
    COPY_ADDR_FROM(value->client_prefix, src_addr->in6_u.u6_addr8);
    if (!value->is_static) {
        bool is_ancestor =
            ip_addr_equal_x(dst_addr, &value->trigger_addr) && view->dport == value->trigger_port;
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
                                                                  const struct tc_nat_view *view,
                                                                  const struct in6_addr *src_addr,
                                                                  const struct in6_addr *dst_addr,
                                                                  u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = view->sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = nat6_outer_protocol(view);

    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (value) {
        if (!nat6_is_same_prefix(value->client_prefix, src_addr, npt_id_mask)) {
            update_ipv6_cache_value(skb, view, src_addr, dst_addr, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat6_timer_value *
create_ct6_egress(struct __sk_buff *skb, const struct tc_nat_view *view,
                  const struct in6_addr *src_addr, const struct in6_addr *dst_addr, u8 npt_id_mask,
                  u32 ifindex, u8 is_allow_reuse, bool is_static, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = view->sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = nat6_outer_protocol(view);

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.gress = NAT_MAPPING_EGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    COPY_ADDR_FROM(new_value.client_prefix, src_addr->in6_u.u6_addr8);
    new_value.is_allow_reuse = is_allow_reuse;
    new_value.is_static = is_static ? 1 : 0;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;
    COPY_ADDR_FROM(new_value.trigger_addr.in6_u.u6_addr32, dst_addr->in6_u.u6_addr32);
    new_value.trigger_port = view->dport;

    return nat6_insert_timer(&key, &new_value);
}

#define L4_CSUM_REPLACE_U64_OR_SHOT(log, skb_ptr, csum_offset, old_val, new_val, flags)            \
    do {                                                                                           \
        int _ret;                                                                                  \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) >> 32, (new_val) >> 32,         \
                                   flags | 4);                                                     \
        if (_ret) {                                                                                \
            log("l4_csum_replace high 32bit err: %d", _ret);                                       \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
        _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, (old_val) & 0xFFFFFFFF,                   \
                                   (new_val) & 0xFFFFFFFF, flags | 4);                             \
        if (_ret) {                                                                                \
            log("l4_csum_replace low 32bit err: %d", _ret);                                        \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int ipv6_egress_prefix_check_and_replace(struct __sk_buff *skb,
                                                                const struct tc_nat_view *view,
                                                                const struct in6_addr *src_addr,
                                                                const struct in6_addr *dst_addr,
                                                                u32 l3_offset, u32 ifindex) {
    int ret;
    u8 proto = nat6_outer_protocol(view);

    if (wan_ro_prefix6.b[0] == 0) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);

    struct nat6_timer_value *ct_value =
        lookup_ct6_egress(skb, view, src_addr, dst_addr, npt_id_mask);
    if (ct_value) {
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
        nat6_metric_accumulate(skb, false, ct_value);
        if (!ct_value->need_prefix_replace) {
            return TC_ACT_UNSPEC;
        }
        goto do_nptv6;
    }

    struct static_nat6_mapping_value *static_val =
        nat6_check_egress_static(proto, src_addr, view->sport);

    bool is_icmpx_error = nat6_is_icmp_error(view);
    bool allow_create = nat6_allows_create_pkt(proto, view->tcp_phase, is_icmpx_error);

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
    ct_value = create_ct6_egress(skb, view, src_addr, dst_addr, npt_id_mask, ifindex, reuse,
                                 static_val != NULL, need_prefix_replace);
    if (!ct_value) {
        return TC_ACT_SHOT;
    }
    nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
    nat6_metric_accumulate(skb, false, ct_value);
    if (!need_prefix_replace) {
        return TC_ACT_UNSPEC;
    }

do_nptv6:
    if (nat6_is_icmp_error(view)) {
        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, src_addr->in6_u.u6_addr32);
        new_ip_prefix = (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        u32 error_sender_offset = l3_offset + offsetof(struct ipv6hdr, saddr);
        u32 inner_l3_ip_dst_offset =
            nat6_icmp_error_l3_offset(view) + offsetof(struct ipv6hdr, daddr);

        __be64 old_sender_ip_prefix, new_sender_ip_prefix;
#if defined(LAND_ARCH_RISCV)
        if (bpf_skb_load_bytes(skb, error_sender_offset, &old_sender_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        if ((u64)error_sender_offset + sizeof(old_sender_ip_prefix) > MAX_OFFSET)
            return TC_ACT_SHOT;
        char *data = (char *)(long)skb->data;
        char *data_end = (char *)(long)skb->data_end;
        char *p = data + error_sender_offset;
        barrier_var(p);
        if (p + sizeof(old_sender_ip_prefix) > data_end) {
            if (bpf_skb_pull_data(skb, error_sender_offset + sizeof(old_sender_ip_prefix)) != 0)
                return TC_ACT_SHOT;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            p = data + error_sender_offset;
            barrier_var(p);
            if (p + sizeof(old_sender_ip_prefix) > data_end) return TC_ACT_SHOT;
        }
        old_sender_ip_prefix = *(__be64 *)p;
#endif
        new_sender_ip_prefix =
            (old_sender_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        u32 inner_l4_checksum_offset = 0;
        if (nat6_l4_checksum(view->icmp_inner_l4_offset, view->icmp_inner_l4_protocol,
                             &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_dst_offset, &new_ip_prefix, 8, 0);
        if (ret) {
            ld_from_lan_log("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_lan_log, skb, inner_l4_checksum_offset, old_ip_prefix,
                                    new_ip_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_lan_log, skb, l4_checksum_offset, old_ip_prefix,
                                    new_ip_prefix, 0);

        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);

        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            ld_from_lan_log("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        bpf_skb_store_bytes(skb, error_sender_offset, &new_sender_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_lan_log, skb, l4_checksum_offset, old_sender_ip_prefix,
                                    new_sender_ip_prefix, BPF_F_PSEUDO_HDR);

    } else {
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 ip_src_offset = l3_offset + offsetof(struct ipv6hdr, saddr);

        __be64 old_ip_prefix, new_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, src_addr->in6_u.u6_addr32);
        new_ip_prefix = (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);
        bpf_skb_store_bytes(skb, ip_src_offset, &new_ip_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_lan_log, skb, l4_checksum_offset, old_ip_prefix,
                                    new_ip_prefix, BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
}

static __always_inline struct nat6_timer_value *lookup_ct6_ingress(const struct tc_nat_view *view,
                                                                   const struct in6_addr *dst_addr,
                                                                   u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = view->dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = nat6_outer_protocol(view);

    return bpf_map_lookup_elem(&nat6_timer_map, &key);
}

static __always_inline struct nat6_timer_value *
create_ct6_ingress(struct __sk_buff *skb, const struct tc_nat_view *view,
                   const struct in6_addr *src_addr, const struct in6_addr *dst_addr, u8 npt_id_mask,
                   u32 ifindex, const __be64 *client_prefix_hint, bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = view->dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = nat6_outer_protocol(view);

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.gress = NAT_MAPPING_INGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    COPY_ADDR_FROM(new_value.trigger_addr.in6_u.u6_addr8, src_addr->in6_u.u6_addr32);
    new_value.trigger_port = view->sport;
    COPY_ADDR_FROM(new_value.client_prefix, client_prefix_hint);
    new_value.is_allow_reuse = 1;
    new_value.is_static = 1;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline int ipv6_ingress_prefix_check_and_replace(struct __sk_buff *skb,
                                                                 const struct tc_nat_view *view,
                                                                 const struct in6_addr *src_addr,
                                                                 const struct in6_addr *dst_addr,
                                                                 u32 l3_offset, u32 ifindex) {
    int ret = 0;
    __be64 local_client_prefix = {0};
    u8 proto = nat6_outer_protocol(view);

    if (wan_ro_prefix6.b[0] == 0) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);

    bool is_icmpx = nat6_is_icmp_error(view);
    bool allow_create = nat6_allows_create_pkt(proto, view->tcp_phase, is_icmpx);
    bool need_prefix_replace = false;

    struct nat6_timer_value *ct_value = lookup_ct6_ingress(view, dst_addr, npt_id_mask);
    if (ct_value) {
        bool ct_is_static = ct_value->is_static != 0;

        if (!ct_is_static) {
            if (ct_value->is_allow_reuse == 0 && proto != NEXTHDR_ICMP) {
                if (!ip_addr_equal_x(src_addr, &ct_value->trigger_addr) ||
                    view->sport != ct_value->trigger_port) {
                    // ld_from_wan_log("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                    // ld_from_wan_log("src info: [%pI6]:%u", src_addr, bpf_ntohs(view->sport));
                    // ld_from_wan_log("trigger ip: [%pI6]:%u,", &ct_value->trigger_addr,
                    //                 bpf_ntohs(ct_value->trigger_port));
                    return TC_ACT_SHOT;
                }
            }
        }

        COPY_ADDR_FROM(&local_client_prefix, ct_value->client_prefix);
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
        nat6_metric_accumulate(skb, true, ct_value);

        __be64 dst_prefix;
        COPY_ADDR_FROM(&dst_prefix, dst_addr->in6_u.u6_addr8);
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

    ret = nat6_check_ingress_static(proto, dst_addr, view->dport, &local_client_prefix);
    bool is_static = (ret != NAT6_STATIC_MISS);
    need_prefix_replace = (ret == NAT6_STATIC_REPLACE);

    __be64 client_prefix_hint = 0;
    if (ret == NAT6_STATIC_REPLACE) {
        client_prefix_hint = local_client_prefix;
    } else if (ret == NAT6_STATIC_PASS) {
        COPY_ADDR_FROM(&client_prefix_hint, dst_addr->in6_u.u6_addr8);
    }

    if (!allow_create) {
        if (!is_static) return TC_ACT_SHOT;
        goto do_ingress_nptv6;
    }

    if (!is_static) {
        ld_from_wan_log("ingress dynamic no CT, l4_proto: %u, dst_port: %04x", proto, view->dport);
        return TC_ACT_SHOT;
    }

    ct_value = create_ct6_ingress(skb, view, src_addr, dst_addr, npt_id_mask, ifindex,
                                  &client_prefix_hint, need_prefix_replace);
    if (ct_value) {
        nat6_ct_advance_pkt(proto, view->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
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
        u32 inner_l3_ip_src_offset =
            nat6_icmp_error_l3_offset(view) + offsetof(struct ipv6hdr, saddr);

        __be64 old_inner_ip_prefix;
#if defined(LAND_ARCH_RISCV)
        if (bpf_skb_load_bytes(skb, inner_l3_ip_src_offset, &old_inner_ip_prefix, 8)) {
            return TC_ACT_SHOT;
        }
#else
        if ((u64)inner_l3_ip_src_offset + sizeof(old_inner_ip_prefix) > MAX_OFFSET)
            return TC_ACT_SHOT;
        char *data = (char *)(long)skb->data;
        char *data_end = (char *)(long)skb->data_end;
        char *p = data + inner_l3_ip_src_offset;
        barrier_var(p);
        if (p + sizeof(old_inner_ip_prefix) > data_end) {
            if (bpf_skb_pull_data(skb, inner_l3_ip_src_offset + sizeof(old_inner_ip_prefix)) != 0)
                return TC_ACT_SHOT;
            data = (char *)(long)skb->data;
            data_end = (char *)(long)skb->data_end;
            p = data + inner_l3_ip_src_offset;
            barrier_var(p);
            if (p + sizeof(old_inner_ip_prefix) > data_end) return TC_ACT_SHOT;
        }
        old_inner_ip_prefix = *(__be64 *)p;
#endif

        u32 inner_l4_checksum_offset = 0;
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(view->icmp_inner_l4_offset, view->icmp_inner_l4_protocol,
                             &inner_l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }
        u16 old_inner_l4_checksum, new_inner_l4_checksum;
        READ_SKB_U16(skb, inner_l4_checksum_offset, old_inner_l4_checksum);

        ret = bpf_skb_store_bytes(skb, inner_l3_ip_src_offset, &local_client_prefix, 8, 0);
        if (ret) {
            ld_from_wan_log("bpf_skb_store_bytes err: %d", ret);
            return TC_ACT_SHOT;
        }

        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_wan_log, skb, inner_l4_checksum_offset,
                                    old_inner_ip_prefix, local_client_prefix, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_wan_log, skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, 0);
        READ_SKB_U16(skb, inner_l4_checksum_offset, new_inner_l4_checksum);
        ret = bpf_l4_csum_replace(skb, l4_checksum_offset, old_inner_l4_checksum,
                                  new_inner_l4_checksum, 2);
        if (ret) {
            ld_from_wan_log("2 - bpf_l4_csum_replace err: %d", ret);
            return TC_ACT_SHOT;
        }

        u32 ipv6_dst_offset = l3_offset + offsetof(struct ipv6hdr, daddr);
        bpf_skb_store_bytes(skb, ipv6_dst_offset, &local_client_prefix, 8, 0);
        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_wan_log, skb, l4_checksum_offset, old_inner_ip_prefix,
                                    local_client_prefix, BPF_F_PSEUDO_HDR);
    } else {
        u32 l4_checksum_offset = 0;
        if (nat6_l4_checksum(view->l4_offset, proto, &l4_checksum_offset)) {
            return TC_ACT_SHOT;
        }

        u32 dst_ip_offset = l3_offset + offsetof(struct ipv6hdr, daddr);

        __be64 old_ip_prefix;
        COPY_ADDR_FROM(&old_ip_prefix, dst_addr->in6_u.u6_addr32);
        bpf_skb_store_bytes(skb, dst_ip_offset, &local_client_prefix, 8, 0);

        L4_CSUM_REPLACE_U64_OR_SHOT(ld_from_wan_log, skb, l4_checksum_offset, old_ip_prefix,
                                    local_client_prefix, BPF_F_PSEUDO_HDR);
    }

    return TC_ACT_UNSPEC;
}

#endif /* LD_NAT6_V3_H */
