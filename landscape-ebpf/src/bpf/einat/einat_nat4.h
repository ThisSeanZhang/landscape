// SPDX-FileCopyrightText: 2023-2024 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//
// The helpers in this file are derived from the einat-ebpf project:
//   https://github.com/EHfive/einat-ebpf
#ifndef __LD_EINAT_NAT4_H__
#define __LD_EINAT_NAT4_H__

#include <vmlinux.h>

#include "base/printk.h"
#include "nat/nat_common.h"

static __always_inline int icmpx_err_l3_offset(int l4_off) {
    return l4_off + sizeof(struct icmphdr);
}

static __always_inline int bpf_write_port(struct __sk_buff *skb, int port_off, __be16 to_port) {
    return bpf_skb_store_bytes(skb, port_off, &to_port, sizeof(to_port), 0);
}

#define L3_CSUM_REPLACE_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, size)                      \
    do {                                                                                           \
        int _ret = bpf_l3_csum_replace(skb_ptr, csum_offset, old_val, new_val, size);              \
        if (_ret) {                                                                                \
            bpf_printk("l3_csum_replace err: %d", _ret);                                           \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

#define L4_CSUM_REPLACE_OR_SHOT(skb_ptr, csum_offset, old_val, new_val, len_plus_flags)            \
    do {                                                                                           \
        int _ret = bpf_l4_csum_replace(skb_ptr, csum_offset, old_val, new_val, len_plus_flags);    \
        if (_ret) {                                                                                \
            bpf_printk("l4_csum_replace err: %d", _ret);                                           \
            return TC_ACT_SHOT;                                                                    \
        }                                                                                          \
    } while (0)

static __always_inline int ipv4_update_csum_inner_macro(struct __sk_buff *skb, u32 l4_csum_off,
                                                        __be32 from_addr, __be16 from_port,
                                                        __be32 to_addr, __be16 to_port,
                                                        bool l4_pseudo, bool l4_mangled_0) {
    u16 csum;
    if (l4_mangled_0) {
        READ_SKB_U16(skb, l4_csum_off, csum);
    }

    if (!l4_mangled_0 || csum != 0) {
        L3_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_port, to_port, 2);

        if (l4_pseudo) {
            L3_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, from_addr, to_addr, 4);
        }
    }
}

static __always_inline int ipv4_update_csum_icmp_err_macro(struct __sk_buff *skb, u32 icmp_csum_off,
                                                           u32 err_ip_check_off,
                                                           u32 err_l4_csum_off, __be32 from_addr,
                                                           __be16 from_port, __be32 to_addr,
                                                           __be16 to_port, bool err_l4_pseudo,
                                                           bool l4_mangled_0) {
    u16 prev_csum;
    u16 curr_csum;
    u16 *tmp_ptr;

    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_ip_check_off, sizeof(*tmp_ptr))) {
        return 1;
    }
    prev_csum = *tmp_ptr;

    L3_CSUM_REPLACE_OR_SHOT(skb, err_ip_check_off, from_addr, to_addr, 4);

    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_ip_check_off, sizeof(*tmp_ptr))) {
        return 1;
    }
    curr_csum = *tmp_ptr;
    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, prev_csum, curr_csum, 2);

    if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_l4_csum_off, sizeof(*tmp_ptr)) == 0) {
        prev_csum = *tmp_ptr;
        ipv4_update_csum_inner_macro(skb, err_l4_csum_off, from_addr, from_port, to_addr, to_port,
                                     err_l4_pseudo, l4_mangled_0);

        if (VALIDATE_READ_DATA(skb, &tmp_ptr, err_l4_csum_off, sizeof(*tmp_ptr))) {
            return 1;
        }
        curr_csum = *tmp_ptr;
        L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, prev_csum, curr_csum, 2);
    }

    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, from_addr, to_addr, 4);
    L4_CSUM_REPLACE_OR_SHOT(skb, icmp_csum_off, from_port, to_port, 2);

    return 0;
}

static __always_inline int modify_headers_v4(struct __sk_buff *skb, bool is_icmpx_error, u8 nexthdr,
                                             u32 current_l3_offset, int l4_off, int err_l4_off,
                                             bool is_modify_source,
                                             const struct nat4_action *action) {
    int ret;
    int l4_to_port_off;
    int l4_to_check_off;
    bool l4_check_pseudo;
    bool l4_check_mangle_0;

    int ip_offset =
        is_modify_source ? offsetof(struct iphdr, saddr) : offsetof(struct iphdr, daddr);

    ret = bpf_skb_store_bytes(skb, current_l3_offset + ip_offset, &action->to_addr.addr,
                              sizeof(action->to_addr.addr), 0);
    if (ret) return ret;

    L3_CSUM_REPLACE_OR_SHOT(skb, current_l3_offset + offsetof(struct iphdr, check),
                            action->from_addr.addr, action->to_addr.addr, 4);

    if (l4_off == 0) return 0;

    switch (nexthdr) {
    case IPPROTO_TCP:
        l4_to_port_off =
            is_modify_source ? offsetof(struct tcphdr, source) : offsetof(struct tcphdr, dest);
        l4_to_check_off = offsetof(struct tcphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = false;
        break;
    case IPPROTO_UDP:
        l4_to_port_off =
            is_modify_source ? offsetof(struct udphdr, source) : offsetof(struct udphdr, dest);
        l4_to_check_off = offsetof(struct udphdr, check);
        l4_check_pseudo = true;
        l4_check_mangle_0 = true;
        break;
    case IPPROTO_ICMP:
        l4_to_port_off = offsetof(struct icmphdr, un.echo.id);
        l4_to_check_off = offsetof(struct icmphdr, checksum);
        l4_check_pseudo = false;
        l4_check_mangle_0 = false;
        break;
    default:
        return 1;
    }

    if (is_icmpx_error) {
        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) {
            l4_to_port_off =
                is_modify_source ? offsetof(struct tcphdr, dest) : offsetof(struct tcphdr, source);
        }

        int icmpx_error_offset =
            is_modify_source ? offsetof(struct iphdr, daddr) : offsetof(struct iphdr, saddr);

        ret = bpf_skb_store_bytes(skb, icmpx_err_l3_offset(l4_off) + icmpx_error_offset,
                                  &action->to_addr.addr, sizeof(action->to_addr.addr), 0);
        if (ret) return ret;

        ret = bpf_write_port(skb, err_l4_off + l4_to_port_off, action->to_port);
        if (ret) return ret;

        if (ipv4_update_csum_icmp_err_macro(
                skb, l4_off + offsetof(struct icmphdr, checksum),
                icmpx_err_l3_offset(l4_off) + offsetof(struct iphdr, check),
                err_l4_off + l4_to_check_off, action->from_addr.addr, action->from_port,
                action->to_addr.addr, action->to_port, l4_check_pseudo, l4_check_mangle_0))
            return TC_ACT_SHOT;

    } else {
        ret = bpf_write_port(skb, l4_off + l4_to_port_off, action->to_port);
        if (ret) return ret;

        u32 l4_csum_off = l4_off + l4_to_check_off;
        u32 flags_mangled = l4_check_mangle_0 ? BPF_F_MARK_MANGLED_0 : 0;

        L4_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, action->from_port, action->to_port,
                                2 | flags_mangled);

        if (l4_check_pseudo) {
            L4_CSUM_REPLACE_OR_SHOT(skb, l4_csum_off, action->from_addr.addr, action->to_addr.addr,
                                    4 | BPF_F_PSEUDO_HDR | flags_mangled);
        }
    }

    return 0;
}

#endif /* __LD_EINAT_NAT4_H__ */
