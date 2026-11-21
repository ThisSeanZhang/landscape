/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_TCP_PHASE_H
#define LAND_NAT_TCP_PHASE_H

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/l4.h"

/* Local TCP phases derived once from the TCP flags byte. */
enum napt_tcp_phase {
    NAPT_TCP_PHASE_NONE = 0,
    NAPT_TCP_PHASE_SYN = 1,
    NAPT_TCP_PHASE_ESTABLISHED = 2,
    NAPT_TCP_PHASE_FIN = 3,
    NAPT_TCP_PHASE_RST = 4,
    NAPT_TCP_PHASE_SYN_ACK = 5,
};

enum napt_tcp_flags {
    NAPT_TCP_LAN_SYN = 1U << 0,
    NAPT_TCP_WAN_SYN = 1U << 1,
    NAPT_TCP_LAN_FIN = 1U << 2,
    NAPT_TCP_WAN_FIN = 1U << 3,
    NAPT_TCP_RST_SEEN = 1U << 4,
    NAPT_TCP_BOTH_SYN = NAPT_TCP_LAN_SYN | NAPT_TCP_WAN_SYN,
    NAPT_TCP_BOTH_FIN = NAPT_TCP_LAN_FIN | NAPT_TCP_WAN_FIN,
};

static __always_inline bool napt_tcp_phase_is_syn(__u8 phase) {
    return phase == NAPT_TCP_PHASE_SYN || phase == NAPT_TCP_PHASE_SYN_ACK;
}

static __always_inline bool napt_tcp_track_flags(__u64 *flags, __u8 tcp_phase, bool from_wan) {
    __u64 seen = *flags;
    __u64 flag = 0;
    if (napt_tcp_phase_is_syn(tcp_phase)) {
        if ((seen & NAPT_TCP_BOTH_FIN) == NAPT_TCP_BOTH_FIN) return false;
        flag = from_wan ? NAPT_TCP_WAN_SYN : NAPT_TCP_LAN_SYN;
    } else if (tcp_phase == NAPT_TCP_PHASE_FIN) {
        flag = from_wan ? NAPT_TCP_WAN_FIN : NAPT_TCP_LAN_FIN;
    } else if (tcp_phase == NAPT_TCP_PHASE_RST) {
        flag = NAPT_TCP_RST_SEEN;
    }
    if (tcp_phase == NAPT_TCP_PHASE_SYN && (seen & NAPT_TCP_RST_SEEN)) {
        /* A fresh SYN after RST reuses the mapping with a new handshake. */
        if (!__sync_bool_compare_and_swap(flags, seen, flag)) return false;
    } else if (flag && !(seen & flag)) {
        __sync_fetch_and_or(flags, flag);
    }
    return true;
}

static __always_inline __u8 napt_tcp_phase_from_flags(__u8 flags) {
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_FIN | TCP_FLAG_ACK)) == TCP_FLAG_ACK)
        return NAPT_TCP_PHASE_ESTABLISHED;
    if (flags & TCP_FLAG_SYN)
        return flags & TCP_FLAG_ACK ? NAPT_TCP_PHASE_SYN_ACK : NAPT_TCP_PHASE_SYN;
    if (flags & TCP_FLAG_RST) return NAPT_TCP_PHASE_RST;
    if (flags & TCP_FLAG_FIN) return NAPT_TCP_PHASE_FIN;
    return NAPT_TCP_PHASE_NONE;
}

#endif /* LAND_NAT_TCP_PHASE_H */
