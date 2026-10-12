#ifndef __LD_WAN_INTRO_DISPATCH_H__
#define __LD_WAN_INTRO_DISPATCH_H__

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/xdp_pipe_def.h"

// Shared by xdp_wan_intro (XDP) and tc_wan_ingress_intro (TC): both feed the
// same pinned wan_intro_dispatch map, so the key/value layout must be identical.
struct dispatch_v4 {
    // Reserve 4 bytes so v4/v6 share the same 8-byte address slot
    u8 _pad[4];
    __be32 daddr;
};

struct dispatch_v6 {
    // IPv6 /64 prefix
    __be64 prefix64;
};

struct dispatch_ppp {
    // PPPoE session id in 32bit slot, sharing key layout with v4/v6
    u8 _pad[4];
    __be32 session_id;
};

struct dispatch_key {
    // Dispatch type: PPPoE inner IPv4/IPv6, direct IPv4/IPv6, or ingress ifindex fallback
    u32 dispatch_type;
    union {
        struct dispatch_v4 v4;
        struct dispatch_v6 v6;
        struct dispatch_ppp ppp;
        u32 ifindex;
    };
};

struct dispatch_value {
    // Prog array index of the matched chain root
    u32 next_pipe_root_index;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dispatch_key);
    __type(value, struct dispatch_value);
    __uint(max_entries, XDP_PIPE_MAX_ENTRIES);
} wan_intro_dispatch_map SEC(".maps");

#endif /* __LD_WAN_INTRO_DISPATCH_H__ */
