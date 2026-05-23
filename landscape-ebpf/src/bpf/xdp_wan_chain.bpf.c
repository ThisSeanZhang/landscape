#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} root_next_stage SEC(".maps");

SEC("xdp")
int xdp_wan_chain_root(struct xdp_md *ctx) {
    bpf_tail_call(ctx, &root_next_stage, 0);
    bpf_tail_call(ctx, &xdp_pipe_exits_wan, 0);
    return XDP_PASS;
}
