/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef LAND_NAT_L4_H
#define LAND_NAT_L4_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define TCP_HDR_MIN_LEN 20U

#define TCP_FLAG_FIN 0x01U
#define TCP_FLAG_SYN 0x02U
#define TCP_FLAG_RST 0x04U
#define TCP_FLAG_ACK 0x10U

#ifndef ICMPV6_ECHO_REQUEST
#define ICMPV6_ECHO_REQUEST 128
#endif
#ifndef ICMPV6_ECHO_REPLY
#define ICMPV6_ECHO_REPLY 129
#endif

_Static_assert(sizeof(struct udphdr) == 8, "UDP header must be exactly 8 bytes");
_Static_assert(sizeof(struct tcphdr) == TCP_HDR_MIN_LEN, "TCP header must be at least 20 bytes");

static __always_inline __u32 tcp_doff_bytes(const struct tcphdr *tcp) {
    return (__u32)tcp->doff * 4U;
}

static __always_inline __u8 tcp_hdr_flags(const struct tcphdr *tcp) {
    return (tcp->fin ? TCP_FLAG_FIN : 0U) | (tcp->syn ? TCP_FLAG_SYN : 0U) |
           (tcp->rst ? TCP_FLAG_RST : 0U) | (tcp->ack ? TCP_FLAG_ACK : 0U);
}

#endif /* LAND_NAT_L4_H */
