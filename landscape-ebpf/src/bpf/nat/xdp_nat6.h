#ifndef __LD_XDP_NAT6_H__
#define __LD_XDP_NAT6_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/ipv6.h"
#include "base/tcp_phase.h"
#include "nat/nat_common.h"
#include "nat/nat6_ct.h"
#include "nat/xdp_csum_helpers.h"

static __always_inline int xdp_nat6_update_quoted_checksum(struct xdp_md *ctx,
                                                           const struct ip6_scan_offsets *off,
                                                           __wsum addr_delta, __sum16 *outer_sum) {
    u32 inner_csum_off = 0;
    if (nat6_l4_checksum(off->icmp_inner_l4_offset, off->icmp_inner_l4_protocol, &inner_csum_off))
        return -1;
    if (inner_csum_off + sizeof(__sum16) > off->icmp_quote_end) return 0;

    __sum16 old_sum;
    if (bpf_xdp_load_bytes(ctx, inner_csum_off, &old_sum, sizeof(old_sum))) return -1;
    __sum16 new_sum = nat6_apply_l4_checksum(old_sum, addr_delta, off->icmp_inner_l4_protocol);
    if (bpf_xdp_store_bytes(ctx, inner_csum_off, &new_sum, sizeof(new_sum))) return -1;

    __be32 from = old_sum, to = new_sum;
    *outer_sum = xdp_csum_apply(*outer_sum, bpf_csum_diff(&from, 4, &to, 4, 0));
    return 0;
}

static __always_inline u8 xdp_nat6_outer_protocol(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset ? NEXTHDR_ICMP : off->l4_protocol;
}

static __always_inline bool xdp_nat6_is_icmp_error(const struct ip6_scan_offsets *off) {
    return off->icmp_inner_l4_offset != 0;
}

static __always_inline u16 xdp_nat6_icmp_error_l3_offset(const struct ip6_scan_offsets *off) {
    return off->icmp_error_l3_offset;
}

static __always_inline int xdp_ipv6_egress_prefix_check_and_replace(
    struct xdp_md *ctx, void *data, void *data_end, u32 wan_if, u32 mark,
    const struct ip6_scan_offsets *off, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, __be16 sport, __be16 dport) {
    u32 l3_offset = off->l3_offset;
    u8 outer_proto = xdp_nat6_outer_protocol(off);

    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(off, src_addr, sport, dst_addr, dport, true, mark,
                                             wan_if, (u64)(long)data_end - (u64)(long)data, &trans))
        return -1;
    if (!trans.replace) return 0;
    bool is_icmpx_error = off->icmp_inner_l4_offset != 0;
    if (is_icmpx_error) {
        u32 err_sender_off = l3_offset + offsetof(struct ipv6hdr, saddr);
        __be64 old_sender_prefix;
        if (bpf_xdp_load_bytes(ctx, err_sender_off, &old_sender_prefix, sizeof(old_sender_prefix)))
            return -1;

        u32 inner_dst_off = xdp_nat6_icmp_error_l3_offset(off) + offsetof(struct ipv6hdr, daddr);
        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(off->l4_offset, outer_proto, &l4_csum_off)) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, src_addr->in6_u.u6_addr32, 8);

        __be64 new_ip_prefix =
            (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __be64 new_sender_prefix =
            (old_sender_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);

        __be16 outer_csum;
        if (bpf_xdp_load_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
        outer_csum = xdp_csum_apply(outer_csum, addr_delta);

        if (xdp_nat6_update_quoted_checksum(ctx, off, addr_delta, &outer_csum)) return -1;
        if (bpf_xdp_store_bytes(ctx, inner_dst_off, &new_ip_prefix, sizeof(new_ip_prefix)))
            return -1;

        if (bpf_xdp_store_bytes(ctx, err_sender_off, &new_sender_prefix, sizeof(new_sender_prefix)))
            return -1;
        __wsum sender_delta =
            bpf_csum_diff((__u32 *)&old_sender_prefix, 8, (__u32 *)&new_sender_prefix, 8, 0);
        outer_csum = xdp_csum_apply(outer_csum, sender_delta);
        if (bpf_xdp_store_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
    } else {
        u32 ip_src_off = l3_offset + offsetof(struct ipv6hdr, saddr);
        void *src_ptr = data + ip_src_off;
        if (src_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, src_addr->in6_u.u6_addr32, 8);

        __be64 new_ip_prefix =
            (old_ip_prefix & wan_ro_npt_mask) | (wan_ro_prefix6.q & ~wan_ro_npt_mask);

        __builtin_memcpy(src_ptr, &new_ip_prefix, 8);
        if (off->frag_code == LAND_FRAG_NON_INITIAL) return 0;

        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(off->l4_offset, outer_proto, &l4_csum_off)) return -1;
        __be16 *csum_ptr = data + l4_csum_off;
        if ((void *)(csum_ptr + 1) > data_end) return -1;
        __wsum delta = bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&new_ip_prefix, 8, 0);
        *csum_ptr = nat6_apply_l4_checksum(*csum_ptr, delta, outer_proto);
    }

    return 0;
}

static __always_inline int xdp_ipv6_ingress_prefix_check_and_replace(
    struct xdp_md *ctx, void *data, void *data_end, u32 wan_if, u32 mark,
    const struct ip6_scan_offsets *off, const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr, __be16 sport, __be16 dport, bool *out_is_static) {
    u8 outer_proto = xdp_nat6_outer_protocol(off);
    u32 l3_offset = off->l3_offset;
    struct nat6_translation trans = {};
    if (!wan_ro_prefix6.b[0] || nat6_resolve(off, dst_addr, dport, src_addr, sport, false, mark,
                                             wan_if, (u64)(long)data_end - (u64)(long)data, &trans))
        return -1;
    __be64 local_client_prefix = trans.client_prefix;
    __be64 dst_prefix;
    __builtin_memcpy(&dst_prefix, dst_addr, sizeof(dst_prefix));
    *out_is_static = trans.is_static;
    if (!trans.replace || dst_prefix == local_client_prefix) return trans.is_static ? 1 : 0;
    bool is_icmpx_error = xdp_nat6_is_icmp_error(off);
    if (is_icmpx_error) {
        u32 inner_src_off = xdp_nat6_icmp_error_l3_offset(off) + offsetof(struct ipv6hdr, saddr);
        __be64 old_inner_ip_prefix;
        if (bpf_xdp_load_bytes(ctx, inner_src_off, &old_inner_ip_prefix,
                               sizeof(old_inner_ip_prefix)))
            return -1;

        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(off->l4_offset, outer_proto, &l4_csum_off)) return -1;

        __wsum addr_delta =
            bpf_csum_diff((__u32 *)&old_inner_ip_prefix, 8, (__u32 *)&local_client_prefix, 8, 0);

        __be16 outer_csum;
        if (bpf_xdp_load_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
        outer_csum = xdp_csum_apply(outer_csum, addr_delta);

        if (xdp_nat6_update_quoted_checksum(ctx, off, addr_delta, &outer_csum)) return -1;
        if (bpf_xdp_store_bytes(ctx, inner_src_off, &local_client_prefix,
                                sizeof(local_client_prefix)))
            return -1;

        u32 dst_ip_off = l3_offset + offsetof(struct ipv6hdr, daddr);
        if (bpf_xdp_store_bytes(ctx, dst_ip_off, &local_client_prefix, sizeof(local_client_prefix)))
            return -1;

        outer_csum = xdp_csum_apply(outer_csum, addr_delta);
        if (bpf_xdp_store_bytes(ctx, l4_csum_off, &outer_csum, sizeof(outer_csum))) return -1;
    } else {
        u32 dst_ip_off = l3_offset + offsetof(struct ipv6hdr, daddr);
        void *dst_ptr = data + dst_ip_off;
        if (dst_ptr + 8 > data_end) return -1;

        __be64 old_ip_prefix;
        __builtin_memcpy(&old_ip_prefix, dst_addr->in6_u.u6_addr32, 8);

        __builtin_memcpy(dst_ptr, &local_client_prefix, 8);
        if (off->frag_code == LAND_FRAG_NON_INITIAL) return 0;

        u32 l4_csum_off = 0;
        if (nat6_l4_checksum(off->l4_offset, outer_proto, &l4_csum_off)) return -1;
        __be16 *csum_ptr = data + l4_csum_off;
        if ((void *)(csum_ptr + 1) > data_end) return -1;
        __wsum delta =
            bpf_csum_diff((__u32 *)&old_ip_prefix, 8, (__u32 *)&local_client_prefix, 8, 0);
        *csum_ptr = nat6_apply_l4_checksum(*csum_ptr, delta, outer_proto);
    }

    return 0;
}

#endif /* __LD_XDP_NAT6_H__ */
