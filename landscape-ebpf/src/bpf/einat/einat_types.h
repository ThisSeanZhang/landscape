// SPDX-FileCopyrightText: 2023-2024 Huang-Huang Bao
// SPDX-License-Identifier: GPL-2.0-or-later
//
// The enums in this file are derived from the einat-ebpf project:
//   https://github.com/EHfive/einat-ebpf
#ifndef __LD_EINAT_TYPES_H__
#define __LD_EINAT_TYPES_H__

#include <vmlinux.h>

// ICMP message classification
enum {
    ICMP_ERROR_MSG,
    ICMP_QUERY_MSG,
    ICMP_ACT_UNSPEC,
    ICMP_ACT_SHOT,
};

// connection type of a packet
enum {
    PKT_CONNLESS_V2,
    PKT_TCP_DATA_V2,
    PKT_TCP_SYN_V2,
    PKT_TCP_RST_V2,
    PKT_TCP_FIN_V2,
    PKT_TCP_ACK_V2,
};

#endif /* __LD_EINAT_TYPES_H__ */
