#ifndef __LD_PIPELINE_H_
#define __LD_PIPELINE_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../landscape.h"

struct xdp_pipe_meta {
    u32 mark;
    u32 target_ifindex;
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

#define XDP_DOCKER_HANDOFF_MAGIC 0x4C444844

struct xdp_docker_handoff {
    u32 magic;
    u32 mark;
    u32 target_ifindex;
};

static __always_inline int xdp_set_docker_meta(struct xdp_md *ctx,
                                               const struct xdp_docker_handoff *ho) {
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*ho));
    if (ret) return ret;
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(*ho) > data) return -1;
    __builtin_memcpy(data_meta, ho, sizeof(*ho));
    return 0;
}

#endif /* __LD_PIPELINE_H_ */
