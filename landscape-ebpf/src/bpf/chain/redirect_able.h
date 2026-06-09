#ifndef __LD_XDP_REDIRECT_ABLE_H_
#define __LD_XDP_REDIRECT_ABLE_H_

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

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

#endif /* __LD_XDP_REDIRECT_ABLE_H_ */
