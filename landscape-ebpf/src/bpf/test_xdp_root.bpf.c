#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"
#include "pipeline/chain.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} root_next_stage SEC(".maps");

SEC("xdp")
int xdp_test_root(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {.mark = 0xCAFE};
    int ret;

    ret = xdp_set_meta(ctx, &meta);
    if (ret) {
        bpf_printk("[root] xdp_set_meta failed: %d", ret);
        return XDP_DROP;
    }

    bpf_printk("[root] mark=0x%x, tailcalling stage1", meta.mark);

    bpf_tail_call(ctx, &root_next_stage, 0);
    bpf_tail_call(ctx, &xdp_pipe_exits, XDP_PIPE_EXIT_WAN_ROUTE);

    bpf_printk("[root] all tailcalls failed");
    return XDP_PASS;
}
