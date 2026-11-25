#ifndef LD_NAT6_V3_H
#define LD_NAT6_V3_H
#include <vmlinux.h>
#include "base/printk.h"
#include "base/tcp_phase.h"
#include "base/ipv6.h"
#include "frag/tc_frag6.h"
#include "nat/nat_common.h"
#include "nat/nat6_ct.h"
#include "nat/xdp_csum_helpers.h"

static __always_inline __u8 nat6_outer_protocol(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset ? NEXTHDR_ICMP : off->l4_protocol;
}

static __always_inline bool nat6_is_icmp_error(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset != 0;
}

static __always_inline __be64 nat6_wan_prefix(__be64 prefix) {
    return (prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);
}

static __always_inline int nat6_modify_icmp_error(struct __sk_buff *skb,
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

    char *data = skb_data(skb);
    char *data_end = skb_data_end(skb);
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

/* Non-initial fragment: the address prefix is the only translated field present. */
static __always_inline int nat6_modify_fragment(struct __sk_buff *skb,
                                                const struct ip6_scan_offsets *off, u8 direction,
                                                __be64 old_prefix, __be64 new_prefix) {
    u32 offset =
        off->l3_offset + (direction == LAND_FRAG_FROM_LAN ? offsetof(struct ipv6hdr, saddr)
                                                          : offsetof(struct ipv6hdr, daddr));
    /* tc_nat_read6 has already pulled the outer IPv6 header into the linear part of the skb. */
    char *addr = skb_data(skb) + offset;
    barrier_var(addr);
    if (addr + sizeof(new_prefix) > skb_data_end(skb)) return TC_ACT_SHOT;
    __builtin_memcpy(addr, &new_prefix, sizeof(new_prefix));

    /* -ENOTSUPP is expected for skb checksum modes other than CHECKSUM_COMPLETE. */
    bpf_csum_update(skb, nat6_prefix_diff(old_prefix, new_prefix));
    return TC_ACT_UNSPEC;
}

/* Unfragmented or first fragment: translate the address prefix and the transport checksum. */
static __always_inline int nat6_modify_outer(struct __sk_buff *skb,
                                             const struct ip6_scan_offsets *off, u8 direction,
                                             __be64 old_prefix, __be64 new_prefix) {
    u32 offset =
        off->l3_offset + (direction == LAND_FRAG_FROM_LAN ? offsetof(struct ipv6hdr, saddr)
                                                          : offsetof(struct ipv6hdr, daddr));
    /* tc_nat_read6 has already pulled the outer IPv6 header into the linear part of the skb. */
    char *addr = skb_data(skb) + offset;
    barrier_var(addr);
    if (addr + sizeof(new_prefix) > skb_data_end(skb)) return TC_ACT_SHOT;
    __builtin_memcpy(addr, &new_prefix, sizeof(new_prefix));

    __wsum prefix_diff = nat6_prefix_diff(old_prefix, new_prefix);
    /* -ENOTSUPP is expected for skb checksum modes other than CHECKSUM_COMPLETE. */
    bpf_csum_update(skb, prefix_diff);

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
    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(off, src_addr, sport, dst_addr, dport, true, skb->mark,
                                             ifindex, skb->len, &trans))
        return TC_ACT_SHOT;

    /* nat6_resolve() authorized the flow; cache the first fragment before translating it. */
    frag6_cache_store_first(off, src_addr, dst_addr, sport, dport, LAND_FRAG_FROM_LAN);

    if (!trans.replace) return TC_ACT_UNSPEC;

    bool is_icmp_error = nat6_is_icmp_error(off);
    if (unlikely(is_icmp_error)) return nat6_modify_icmp_error(skb, off, false, 0);

    __be64 old_ip_prefix;
    COPY_ADDR_FROM(&old_ip_prefix, src_addr->in6_u.u6_addr32);
    __be64 new_ip_prefix = nat6_wan_prefix(old_ip_prefix);
    if (unlikely(off->frag_code == LAND_FRAG_NON_INITIAL))
        return nat6_modify_fragment(skb, off, LAND_FRAG_FROM_LAN, old_ip_prefix, new_ip_prefix);
    return nat6_modify_outer(skb, off, LAND_FRAG_FROM_LAN, old_ip_prefix, new_ip_prefix);
}

static __always_inline int ipv6_ingress_prefix_check_and_replace(
    struct __sk_buff *skb, const struct ip6_scan_offsets *off, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, __be16 sport, __be16 dport, u32 ifindex) {
    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(off, dst_addr, dport, src_addr, sport, false,
                                             skb->mark, ifindex, skb->len, &trans))
        return TC_ACT_SHOT;

    /* nat6_resolve() authorized the flow; cache the first fragment before translating it. */
    frag6_cache_store_first(off, src_addr, dst_addr, sport, dport, LAND_FRAG_FROM_WAN);

    __be64 local_client_prefix = trans.client_prefix;
    __be64 dst_prefix;
    __builtin_memcpy(&dst_prefix, dst_addr, sizeof(dst_prefix));
    int ret = TC_ACT_UNSPEC;
    if (trans.replace && dst_prefix != local_client_prefix) {
        bool is_icmp_error = nat6_is_icmp_error(off);
        if (unlikely(is_icmp_error)) {
            ret = nat6_modify_icmp_error(skb, off, true, local_client_prefix);
        } else {
            __be64 old_ip_prefix;
            COPY_ADDR_FROM(&old_ip_prefix, dst_addr->in6_u.u6_addr32);
            if (unlikely(off->frag_code == LAND_FRAG_NON_INITIAL))
                ret = nat6_modify_fragment(skb, off, LAND_FRAG_FROM_WAN, old_ip_prefix,
                                           local_client_prefix);
            else
                ret = nat6_modify_outer(skb, off, LAND_FRAG_FROM_WAN, old_ip_prefix,
                                        local_client_prefix);
        }
        if (ret == TC_ACT_SHOT) return TC_ACT_SHOT;
    }
    if (trans.is_static) {
        u32 mark = skb->mark;
        barrier_var(mark);
        skb->mark = replace_cache_mask(mark, INGRESS_STATIC_MARK);
    }
    return ret;
}

#endif /* LD_NAT6_V3_H */
