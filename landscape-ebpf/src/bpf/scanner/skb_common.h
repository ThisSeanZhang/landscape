#ifndef __LD_SKB_SCANNER_COMMON_H__
#define __LD_SKB_SCANNER_COMMON_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>

#include "../landscape.h"
#include "../pkg_def.h"
#include "scan_types.h"

enum land_scan_result {
    LD_SCAN_OK = 0,
    LD_SCAN_ERR = 2,
    LD_SCAN_UNSPEC = -1,
};

enum packet_scan_depth {
    LD_SCAN_DEPTH_NONE = 0,
    LD_SCAN_DEPTH_PROTO = 1,
    LD_SCAN_DEPTH_L3 = 2,
    LD_SCAN_DEPTH_FULL = 3,
};

struct ip_scanner_ctx {
    u8 l4_protocol;
    u8 fragment_type;
    u16 fragment_off;
    u16 fragment_id;
    u16 l4_offset;
};

union u_ld_ip {
    __be32 all[4];
    __be32 ip;
    __be32 ip6[4];
    u8 bits[16];
};

static __always_inline bool ld_ip_addr_equal(const union u_ld_ip *a, const union u_ld_ip *b) {
    return a->all[0] == b->all[0] && a->all[1] == b->all[1] && a->all[2] == b->all[2] &&
           a->all[3] == b->all[3];
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

#endif /* __LD_SKB_SCANNER_COMMON_H__ */
