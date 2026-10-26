#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "reader/xdp_l3.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_cb.h"
#include "chain/redirect_able.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

char LICENSE[] SEC("license") = "GPL";

/* Chain id of the owning WAN link; stamped into the packet metadata
 * alongside the mark/target_ifindex written by xdp_lan_route. */
const volatile u32 current_chain = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} root_next_stage SEC(".maps");

SEC("xdp")
int xdp_lan_root(struct xdp_md *ctx) {
    if (xdp_stamp_chain_id(ctx, current_chain) != 0) {
        bpf_printk("[lan_root] stamp chain meta failed, chain=%u", current_chain);
        return XDP_DROP;
    }

    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_root] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_root] target_ifindex=0");
        return XDP_PASS;
    }

    switch (xdp_classify_l3(ctx)) {
    case XDP_L3_V6:
        bpf_tail_call_static(ctx, &root_next_stage, XDP_ROOT_SLOT_V6);
        break;
    case XDP_L3_V4:
        bpf_tail_call_static(ctx, &root_next_stage, XDP_ROOT_SLOT_V4);
        break;
    default:
        // Non-IP packets take no tail call and fall through to the exit.
        break;
    }
    XDP_FROM_LAN_CHAIN_EXIT(ctx);

    bpf_printk("[lan_root] all tailcalls failed");
    return XDP_PASS;
}
