#ifndef LD_NAT6_V3_H
#define LD_NAT6_V3_H
#include <vmlinux.h>
#include "base/printk.h"
#include "base/tcp_phase.h"
#include "base/ipv6.h"
#include "nat/nat_common.h"
#include "nat/nat6_map_ops.h"
#include "nat/nat6_ct_timer.h"
#include "nat/nat_rodata6.h"
#include "nat/xdp_csum_helpers.h"

static __always_inline __u8 nat6_outer_protocol(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset ? NEXTHDR_ICMP : off->l4_protocol;
}

static __always_inline bool nat6_is_icmp_error(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset != 0;
}

static __always_inline int update_ipv6_cache_value(struct __sk_buff *skb,
                                                   const struct in6_addr *src_addr,
                                                   const struct in6_addr *dst_addr, __be16 dport,
                                                   struct nat6_timer_value *value) {
    COPY_ADDR_FROM(value->client_prefix, src_addr->in6_u.u6_addr8);
    if (!value->is_static) {
        bool is_ancestor =
            ip_addr_equal_x(dst_addr, &value->trigger_addr) && dport == value->trigger_port;
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

static __always_inline struct nat6_timer_value *
lookup_ct6_egress(struct __sk_buff *skb, const struct ip6_scan_offsets *off,
                  const struct in6_addr *src_addr, const struct in6_addr *dst_addr, __be16 sport,
                  __be16 dport, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = off->l4_protocol;

    struct nat6_timer_value *value = bpf_map_lookup_elem(&nat6_timer_map, &key);
    if (value) {
        if (!nat6_is_icmp_error(off) &&
            !nat6_is_same_prefix(value->client_prefix, src_addr, npt_id_mask)) {
            update_ipv6_cache_value(skb, src_addr, dst_addr, dport, value);
        }
        return value;
    }
    return NULL;
}

static __always_inline struct nat6_timer_value *
create_ct6_egress(struct __sk_buff *skb, const struct ip6_scan_offsets *off,
                  const struct in6_addr *src_addr, const struct in6_addr *dst_addr, __be16 sport,
                  __be16 dport, u8 npt_id_mask, u32 ifindex, u8 is_allow_reuse, bool is_static,
                  bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = sport;
    COPY_ADDR_FROM(key.client_suffix, src_addr->in6_u.u6_addr8 + 8);
    key.id_byte = src_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = off->l4_protocol;

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
    new_value.trigger_port = dport;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline __wsum nat6_prefix_diff(__be64 old_prefix, __be64 new_prefix) {
    /* IPv6 address fields start at even offsets in both supported L2 layouts. */
    u64 delta = (~old_prefix >> 32) + (u32)~old_prefix + (new_prefix >> 32) + (u32)new_prefix;
    delta = (delta >> 32) + (u32)delta;
    return (delta >> 32) + (u32)delta;
}

static __always_inline __be64 nat6_wan_prefix(__be64 prefix) {
    return (prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);
}

static __always_inline int nat6_rewrite_icmp_error(struct __sk_buff *skb,
                                                   const struct ip6_scan_offsets *off, bool ingress,
                                                   __be64 lan_prefix) {
    u32 outer_addr_off = off->l3_offset + (ingress ? offsetof(struct ipv6hdr, daddr)
                                                   : offsetof(struct ipv6hdr, saddr));
    u32 inner_addr_off = off->icmp_error_l3_offset + (ingress ? offsetof(struct ipv6hdr, saddr)
                                                              : offsetof(struct ipv6hdr, daddr));
    u32 inner_csum_off;
    if (nat6_l4_checksum(off->icmp_inner_l4_offset, off->icmp_inner_l4_protocol, &inner_csum_off))
        return TC_ACT_SHOT;
    u32 inner_csum_end = inner_csum_off + sizeof(__sum16);
    bool has_inner_sum = inner_csum_end <= off->icmp_quote_end;
    /* The quoted prefix follows the outer headers. Only pull the quoted checksum if complete. */
    u32 write_end = has_inner_sum ? inner_csum_end : inner_addr_off + sizeof(__be64);
    if (write_end > MAX_OFFSET || ip6_skb_may_pull(skb, write_end)) return TC_ACT_SHOT;

    char *data = ip6_skb_data(skb);
    char *data_end = ip6_skb_data_end(skb);
    char *inner_addr = data + inner_addr_off;
    char *outer_addr = data + outer_addr_off;
    barrier_var(inner_addr);
    barrier_var(outer_addr);
    if (inner_addr + sizeof(__be64) > data_end || outer_addr + sizeof(__be64) > data_end)
        return TC_ACT_SHOT;

    __be64 old_inner, old_outer;
    __builtin_memcpy(&old_inner, inner_addr, sizeof(old_inner));
    __builtin_memcpy(&old_outer, outer_addr, sizeof(old_outer));
    __be64 new_inner = ingress ? lan_prefix : nat6_wan_prefix(old_inner);
    __be64 new_outer = ingress ? lan_prefix : nat6_wan_prefix(old_outer);
    __builtin_memcpy(inner_addr, &new_inner, sizeof(new_inner));
    __builtin_memcpy(outer_addr, &new_outer, sizeof(new_outer));

    __wsum quote_diff = nat6_prefix_diff(old_inner, new_inner);
    if (has_inner_sum) {
        char *csum = data + inner_csum_off;
        barrier_var(csum);
        if (csum + sizeof(__sum16) > data_end) return TC_ACT_SHOT;
        __sum16 old_sum;
        __builtin_memcpy(&old_sum, csum, sizeof(old_sum));
        __sum16 new_sum = nat6_apply_l4_checksum(old_sum, quote_diff, off->icmp_inner_l4_protocol);
        __builtin_memcpy(csum, &new_sum, sizeof(new_sum));
        /* Both changed fields contribute to the outer ICMPv6 payload checksum. */
        quote_diff = xdp_csum_add(quote_diff, (__u16)~old_sum + (__u32)new_sum);
    }

    u32 outer_csum_off = off->l4_offset + offsetof(struct icmp6hdr, icmp6_cksum);
    if (bpf_l4_csum_replace(skb, outer_csum_off, 0, quote_diff, 0)) return TC_ACT_SHOT;
    __wsum outer_diff = nat6_prefix_diff(old_outer, new_outer);
    bpf_csum_update(skb, outer_diff);
    if (bpf_l4_csum_replace(skb, outer_csum_off, 0, outer_diff, BPF_F_PSEUDO_HDR))
        return TC_ACT_SHOT;
    return TC_ACT_UNSPEC;
}

static __always_inline int nat6_replace_outer_prefix(struct __sk_buff *skb,
                                                     const struct ip6_scan_offsets *off, u32 offset,
                                                     __be64 old_prefix, __be64 new_prefix) {
    /* tc_nat_read6 has already pulled the outer IPv6 header into the linear part of the skb. */
    char *addr = ip6_skb_data(skb) + offset;
    barrier_var(addr);
    if (addr + sizeof(new_prefix) > ip6_skb_data_end(skb)) return TC_ACT_SHOT;
    __builtin_memcpy(addr, &new_prefix, sizeof(new_prefix));

    __wsum prefix_diff = nat6_prefix_diff(old_prefix, new_prefix);
    /* -ENOTSUPP is expected for skb checksum modes other than CHECKSUM_COMPLETE. */
    bpf_csum_update(skb, prefix_diff);
    if (off->frag_code == LAND_FRAG_NON_INITIAL) return TC_ACT_UNSPEC;

    u32 l4_checksum_offset = 0;
    if (nat6_l4_checksum(off->l4_offset, off->l4_protocol, &l4_checksum_offset)) return TC_ACT_SHOT;
    u64 flags = BPF_F_PSEUDO_HDR;
    if (off->l4_protocol == IPPROTO_UDP) flags |= BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE;
    int ret = bpf_l4_csum_replace(skb, l4_checksum_offset, 0, prefix_diff, flags);
    if (ret) {
        ld_log("l4_csum_replace for IPv6 prefix failed: %d", ret);
        return TC_ACT_SHOT;
    }
    return TC_ACT_UNSPEC;
}

static __always_inline int ipv6_egress_prefix_check_and_replace(
    struct __sk_buff *skb, const struct ip6_scan_offsets *off, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, __be16 sport, __be16 dport, u32 ifindex) {
    u32 l3_offset = off->l3_offset;
    u8 ct_proto = off->l4_protocol;

    if (wan_ro_prefix6.b[0] == 0) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);
    bool is_icmpx_error = nat6_is_icmp_error(off);

    struct nat6_timer_value *ct_value =
        lookup_ct6_egress(skb, off, src_addr, dst_addr, sport, dport, npt_id_mask);
    if (ct_value) {
        if (!is_icmpx_error) {
            nat6_ct_advance_pkt(ct_proto, off->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
            nat6_metric_accumulate(skb, false, ct_value);
        }
        if (!ct_value->need_prefix_replace) {
            return TC_ACT_UNSPEC;
        }
        goto do_nptv6;
    }

    struct static_nat6_mapping_value *static_val =
        nat6_check_egress_static(ct_proto, src_addr, sport);

    bool allow_create = nat6_allows_create_pkt(ct_proto, off->tcp_phase, is_icmpx_error);

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
    ct_value = create_ct6_egress(skb, off, src_addr, dst_addr, sport, dport, npt_id_mask, ifindex,
                                 reuse, static_val != NULL, need_prefix_replace);
    if (!ct_value) {
        return TC_ACT_SHOT;
    }
    nat6_ct_advance_pkt(ct_proto, off->tcp_phase, NAT_MAPPING_EGRESS, ct_value);
    nat6_metric_accumulate(skb, false, ct_value);
    if (!need_prefix_replace) {
        return TC_ACT_UNSPEC;
    }

do_nptv6:
    if (is_icmpx_error) return nat6_rewrite_icmp_error(skb, off, false, 0);

    u32 ip_src_offset = l3_offset + offsetof(struct ipv6hdr, saddr);
    __be64 old_ip_prefix;
    COPY_ADDR_FROM(&old_ip_prefix, src_addr->in6_u.u6_addr32);
    return nat6_replace_outer_prefix(skb, off, ip_src_offset, old_ip_prefix,
                                     nat6_wan_prefix(old_ip_prefix));
}

static __always_inline struct nat6_timer_value *
lookup_ct6_ingress(const struct ip6_scan_offsets *off, const struct in6_addr *dst_addr,
                   __be16 dport, u8 npt_id_mask) {
    struct nat6_timer_key key = {0};
    key.client_port = dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = off->l4_protocol;

    return bpf_map_lookup_elem(&nat6_timer_map, &key);
}

static __always_inline struct nat6_timer_value *
create_ct6_ingress(struct __sk_buff *skb, const struct ip6_scan_offsets *off,
                   const struct in6_addr *src_addr, const struct in6_addr *dst_addr, __be16 sport,
                   __be16 dport, u8 npt_id_mask, u32 ifindex, const __be64 *client_prefix_hint,
                   bool need_prefix_replace) {
    struct nat6_timer_key key = {0};
    key.client_port = dport;
    COPY_ADDR_FROM(key.client_suffix, dst_addr->in6_u.u6_addr8 + 8);
    key.id_byte = dst_addr->in6_u.u6_addr8[7] & npt_id_mask;
    key.l4_protocol = off->l4_protocol;

    struct nat6_timer_value new_value = {};
    __builtin_memset(&new_value, 0, sizeof(new_value));
    new_value.create_time = bpf_ktime_get_tai_ns();
    new_value.flow_id = get_flow_id(skb->mark);
    new_value.gress = NAT_MAPPING_INGRESS;
    new_value.cpu_id = bpf_get_smp_processor_id();
    new_value.ifindex = ifindex;
    COPY_ADDR_FROM(new_value.trigger_addr.in6_u.u6_addr8, src_addr->in6_u.u6_addr32);
    new_value.trigger_port = sport;
    COPY_ADDR_FROM(new_value.client_prefix, client_prefix_hint);
    new_value.is_allow_reuse = 1;
    new_value.is_static = 1;
    new_value.need_prefix_replace = need_prefix_replace ? 1 : 0;

    return nat6_insert_timer(&key, &new_value);
}

static __always_inline int ipv6_ingress_prefix_check_and_replace(
    struct __sk_buff *skb, const struct ip6_scan_offsets *off, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, __be16 sport, __be16 dport, u32 ifindex) {
    int ret = 0;
    __be64 local_client_prefix = {0};
    u32 l3_offset = off->l3_offset;
    u8 ct_proto = off->l4_protocol;

    if (wan_ro_prefix6.b[0] == 0) {
        return TC_ACT_SHOT;
    }

    u8 npt_id_mask = (u8)(wan_ro_npt_mask >> 56);

    bool is_icmpx = nat6_is_icmp_error(off);
    bool allow_create = nat6_allows_create_pkt(ct_proto, off->tcp_phase, is_icmpx);
    bool need_prefix_replace = false;

    struct nat6_timer_value *ct_value = lookup_ct6_ingress(off, dst_addr, dport, npt_id_mask);
    if (ct_value) {
        bool ct_is_static = ct_value->is_static != 0;

        if (!ct_is_static) {
            if (ct_value->is_allow_reuse == 0 && ct_proto != NEXTHDR_ICMP) {
                if (!ip_addr_equal_x(src_addr, &ct_value->trigger_addr) ||
                    sport != ct_value->trigger_port) {
                    // ld_from_wan_log("FLOW_ALLOW_REUSE MARK not set, DROP PACKET");
                    // ld_from_wan_log("src info: [%pI6]:%u", src_addr, bpf_ntohs(sport));
                    // ld_from_wan_log("trigger ip: [%pI6]:%u,", &ct_value->trigger_addr,
                    //                 bpf_ntohs(ct_value->trigger_port));
                    return TC_ACT_SHOT;
                }
            }
        }

        COPY_ADDR_FROM(&local_client_prefix, ct_value->client_prefix);
        if (!is_icmpx) {
            nat6_ct_advance_pkt(ct_proto, off->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
            nat6_metric_accumulate(skb, true, ct_value);
        }

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

    ret = nat6_check_ingress_static(ct_proto, dst_addr, dport, &local_client_prefix);
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
        ld_from_wan_log("ingress dynamic no CT, l4_proto: %u, dst_port: %04x", ct_proto, dport);
        return TC_ACT_SHOT;
    }

    ct_value = create_ct6_ingress(skb, off, src_addr, dst_addr, sport, dport, npt_id_mask, ifindex,
                                  &client_prefix_hint, need_prefix_replace);
    if (ct_value) {
        nat6_ct_advance_pkt(ct_proto, off->tcp_phase, NAT_MAPPING_INGRESS, ct_value);
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

    if (is_icmpx) return nat6_rewrite_icmp_error(skb, off, true, local_client_prefix);

    u32 dst_ip_offset = l3_offset + offsetof(struct ipv6hdr, daddr);
    __be64 old_ip_prefix;
    COPY_ADDR_FROM(&old_ip_prefix, dst_addr->in6_u.u6_addr32);
    return nat6_replace_outer_prefix(skb, off, dst_ip_offset, old_ip_prefix, local_client_prefix);
}

#endif /* LD_NAT6_V3_H */
