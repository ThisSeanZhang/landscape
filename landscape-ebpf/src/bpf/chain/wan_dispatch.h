#ifndef __LD_WAN_DISPATCH_H_
#define __LD_WAN_DISPATCH_H_

#include <vmlinux.h>

#include "pipe_limits.h"

// 16-byte WAN ingress dispatch selector key, shared by the XDP WAN intro
// (`wan_intro_dispatch`), the SKB-mode PPPoE stripper (`xdp_skb_pppoe`) and
// the TC WAN ingress intro (`tc_wan_intro`).
//
// Layout (little-endian host):
//   [0..4)   dispatch_type: LANDSCAPE_IPV4_TYPE | LANDSCAPE_IPV6_TYPE |
//            WAN_INTRO_PPP_SESSION_TYPE
//   [4..8)   ingress_ifindex — selector scope. Selectors only match frames
//            ingressing on the iface they were registered for, so two WAN
//            links may reuse the same address or PPPoE session id.
//   [8..16)  v6: destination /64 prefix
//            v4: [8..12) pad, [12..16) daddr (BE)
//            ppp: [8..14) pad, [14..16) session id (BE u16, verbatim from
//                 the PPPoE header — no byte-order conversion on either side)
struct dispatch_v4 {
    u8 _pad[4];
    __be32 daddr;
};

struct dispatch_v6 {
    __be64 prefix64;
};

struct dispatch_ppp {
    u8 _pad[6];
    __be16 session_id;
};

struct dispatch_key {
    u32 dispatch_type;
    u32 ingress_ifindex;
    union {
        struct dispatch_v4 v4;
        struct dispatch_v6 v6;
        struct dispatch_ppp ppp;
    };
};

struct dispatch_value {
    // Logical link chain id, used as the root prog-array key.
    u32 chain_id;
};

#endif /* __LD_WAN_DISPATCH_H_ */
