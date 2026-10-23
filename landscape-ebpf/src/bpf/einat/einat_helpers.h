// SPDX-FileCopyrightText: 2023-2024 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//
// The helpers in this file are derived from the einat-ebpf project:
//   https://github.com/EHfive/einat-ebpf
#ifndef __LD_EINAT_HELPERS_H__
#define __LD_EINAT_HELPERS_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "base/landscape.h"
#include "base/proto_def.h"

static __always_inline bool ld_ip_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
    return a->in6_u.u6_addr32[0] == b->in6_u.u6_addr32[0] &&
           a->in6_u.u6_addr32[1] == b->in6_u.u6_addr32[1] &&
           a->in6_u.u6_addr32[2] == b->in6_u.u6_addr32[2] &&
           a->in6_u.u6_addr32[3] == b->in6_u.u6_addr32[3];
}

static __always_inline int icmp_msg_type(struct icmphdr *icmph) {
    switch (icmph->type) {
    case ICMP_DEST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAMETERPROB:
        return ICMP_ERROR_MSG;
    case ICMP_ECHOREPLY:
    case ICMP_ECHO:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

static __always_inline int icmp6_msg_type(struct icmp6hdr *icmp6h) {
    switch (icmp6h->icmp6_type) {
    case ICMPV6_DEST_UNREACH:
    case ICMPV6_PKT_TOOBIG:
    case ICMPV6_TIME_EXCEED:
    case ICMPV6_PARAMPROB:
        return ICMP_ERROR_MSG;
    case ICMPV6_ECHO_REQUEST:
    case ICMPV6_ECHO_REPLY:
        return ICMP_QUERY_MSG;
    }
    return ICMP_ACT_UNSPEC;
}

#endif /* __LD_EINAT_HELPERS_H__ */
