#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_test_chain_stage(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};
    int ret;

    ret = xdp_get_meta(ctx, &meta);
    if (ret) {
        bpf_printk("[stage] xdp_get_meta failed: %d", ret);
        return XDP_DROP;
    }

    u32 prev_mark = meta.mark;
    meta.mark++;

    ret = xdp_set_meta(ctx, &meta);
    if (ret) {
        bpf_printk("[stage] xdp_set_meta failed: %d", ret);
        return XDP_DROP;
    }

    bpf_printk("[stage] mark %u → %u, tailcalling next", prev_mark, meta.mark);

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);

    bpf_printk("[stage] all tailcalls failed (mark=%u)", meta.mark);
    return XDP_PASS;
}
