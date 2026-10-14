#ifndef __LD_PIPELINE_H_
#define __LD_PIPELINE_H_
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "base/landscape.h"

struct xdp_pipe_meta {
    u32 mark;
    u32 target_ifindex;
    u32 target_chain_id;
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

/* Stamp the owning WAN link's chain id into the packet metadata.  Reuses
 * the metadata area when one is already present (preserving mark and
 * target_ifindex) so repeated stamps never grow the meta room; otherwise
 * allocates it fresh with zeroed fields. */
static __always_inline int xdp_stamp_chain_id(struct xdp_md *ctx, u32 chain_id) {
    struct xdp_pipe_meta meta = {};
    if (xdp_get_meta(ctx, &meta) != 0) {
        int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(meta));
        if (ret) return ret;
    }
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(meta) > data) return -1;
    meta.target_chain_id = chain_id;
    __builtin_memcpy(data_meta, &meta, sizeof(meta));
    return 0;
}

#define XDP_HANDOFF_DOCKER_MAGIC 0x4C444844
#define XDP_HANDOFF_TC_REDIRECT_MAGIC 0x4C445443

struct xdp_docker_handoff_payload {
    u32 mark;
    u32 target_ifindex;
};

struct xdp_tc_redirect_handoff_payload {
    u32 mark;
    u32 target_ifindex;
};

union xdp_handoff_payload {
    struct xdp_docker_handoff_payload docker;
    struct xdp_tc_redirect_handoff_payload tc_redirect;
};

struct xdp_handoff_meta {
    u32 magic;
    union xdp_handoff_payload payload;
};

static __always_inline int xdp_set_handoff_meta(struct xdp_md *ctx,
                                                const struct xdp_handoff_meta *ho) {
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*ho));
    if (ret) return ret;
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(*ho) > data) return -1;
    __builtin_memcpy(data_meta, ho, sizeof(*ho));
    return 0;
}

static __always_inline int xdp_set_docker_meta(struct xdp_md *ctx, u32 mark, u32 target_ifindex) {
    struct xdp_handoff_meta ho = {
        .magic = XDP_HANDOFF_DOCKER_MAGIC,
        .payload.docker = {.mark = mark, .target_ifindex = target_ifindex},
    };
    return xdp_set_handoff_meta(ctx, &ho);
}

static __always_inline int xdp_set_tc_redirect_meta(struct xdp_md *ctx, u32 mark,
                                                    u32 target_ifindex) {
    struct xdp_handoff_meta ho = {
        .magic = XDP_HANDOFF_TC_REDIRECT_MAGIC,
        .payload.tc_redirect = {.mark = mark, .target_ifindex = target_ifindex},
    };
    return xdp_set_handoff_meta(ctx, &ho);
}

static __always_inline bool xdp_has_tc_redirect_meta(struct xdp_md *ctx) {
    void *data_meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (data_meta + sizeof(struct xdp_handoff_meta) > data) return false;
    struct xdp_handoff_meta *ho = data_meta;
    return ho->magic == XDP_HANDOFF_TC_REDIRECT_MAGIC;
}

#endif /* __LD_PIPELINE_H_ */
