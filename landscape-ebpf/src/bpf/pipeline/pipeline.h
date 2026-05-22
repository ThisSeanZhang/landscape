#ifndef __LD_PIPELINE_H_
#define __LD_PIPELINE_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../landscape.h"

#define PIPELINE_COUNT 1024

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, PIPELINE_COUNT);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} xdp_pipe_root_progs SEC(".maps");

struct xdp_pipe_meta {
    u32 mark;
};

static __always_inline int xdp_get_meta(struct xdp_md *ctx, struct xdp_pipe_meta *meta) {
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(*meta) > data) return -1;
    __builtin_memcpy(meta, data_meta, sizeof(*meta));
    return 0;
}

static __always_inline int xdp_set_meta(struct xdp_md *ctx, struct xdp_pipe_meta *meta) {
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret) return ret;
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(*meta) > data) return -1;
    __builtin_memcpy(data_meta, meta, sizeof(*meta));
    return 0;
}

#endif /* __LD_PIPELINE_H_ */
