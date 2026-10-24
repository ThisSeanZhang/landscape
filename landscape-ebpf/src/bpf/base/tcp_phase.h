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
};

static __always_inline __u8 napt_tcp_phase_from_flags(__u8 flags) {
    if (flags & TCP_FLAG_SYN) return NAPT_TCP_PHASE_SYN;
    if (flags & TCP_FLAG_RST) return NAPT_TCP_PHASE_RST;
    if (flags & TCP_FLAG_FIN) return NAPT_TCP_PHASE_FIN;
    if (flags & TCP_FLAG_ACK) return NAPT_TCP_PHASE_ESTABLISHED;
    return NAPT_TCP_PHASE_NONE;
}

#endif /* LAND_NAT_TCP_PHASE_H */
