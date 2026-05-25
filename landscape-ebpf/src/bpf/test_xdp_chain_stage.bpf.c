#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"
#include "pipeline/stage.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} stage_fallback_map SEC(".maps");

SEC("xdp")
int xdp_test_chain_stage(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};
    int ret;

    ret = xdp_get_meta(ctx, &meta);
    if (ret) {
        return XDP_DROP;
    }

    meta.mark++;

    ret = xdp_set_meta(ctx, &meta);
    if (ret) {
        return XDP_DROP;
    }

    bpf_tail_call(ctx, &next_stage, XDP_STAGE_NEXT_LAN);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);

    u32 k = 0;
    u64 *cnt = bpf_map_lookup_elem(&stage_fallback_map, &k);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}
