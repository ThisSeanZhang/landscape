#ifndef __LD_XDP_REDIRECT_ABLE_H_
#define __LD_XDP_REDIRECT_ABLE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "chain/xdp_meta.h"

#define XDP_REDIRECT_ABLE_MAX_ENTRIES 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, XDP_REDIRECT_ABLE_MAX_ENTRIES);
} xdp_redirect_able SEC(".maps");

static __always_inline bool xdp_redirect_target_able(u32 ifindex) {
    u32 *able = bpf_map_lookup_elem(&xdp_redirect_able, &ifindex);
    return able != NULL && *able != 0;
}

static __always_inline int xdp_redirect_or_tc_handoff(struct xdp_md *ctx, u32 target_ifindex,
                                                      u32 mark) {
    if (xdp_redirect_target_able(target_ifindex)) return bpf_redirect(target_ifindex, 0);
    if (xdp_set_tc_redirect_meta(ctx, mark, target_ifindex) != 0) return XDP_DROP;
    return XDP_PASS;
}

#endif /* __LD_XDP_REDIRECT_ABLE_H_ */
