#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "chain/xdp_meta.h"
#include "chain/xdp_lan_maps.h"

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
        return XDP_DROP;
    }

    bpf_tail_call(ctx, &root_next_stage, 0);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);

    return XDP_PASS;
}
