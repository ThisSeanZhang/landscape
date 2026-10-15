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

/* Load ctx data pointers via asm: clang's codegen for these fields can
 * break the verifier's ctx tracking, and the opaque asm value prevents
 * address math from being folded back onto ctx.
 *
 * Note a compiler barrier (`asm volatile("" : "+r"(ctx))`) is NOT an
 * equivalent substitute: it would be needed at EVERY read site.  With a
 * barrier only after bpf_xdp_adjust_meta (the minimal fix for the
 * straight-line chain roots), clang LICM-hoists the field offsets out of
 * any enclosing loop as invariant scalars and dereferences `ctx + reg`
 * inside it — the same "dereference of modified ctx ptr" rejection, just
 * one call-site shape later.  The asm accessors are immune in every shape
 * by construction, and measured no slower than the barrier form. */
#define DEFINE_XDP_CTX_POINTER(FIELD)                                                              \
    static __always_inline void *ctx_##FIELD(const struct xdp_md *ctx) {                           \
        void *ptr;                                                                                 \
        __asm__ __volatile__("%0 = *(u32 *)(%1 + %2)"                                              \
                             : "=r"(ptr)                                                           \
                             : "r"(ctx), "i"(offsetof(struct xdp_md, FIELD)));                     \
        return ptr;                                                                                \
    }
DEFINE_XDP_CTX_POINTER(data)      /* This defines ctx_data(). */
DEFINE_XDP_CTX_POINTER(data_end)  /* This defines ctx_data_end(). */
DEFINE_XDP_CTX_POINTER(data_meta) /* This defines ctx_data_meta(). */
#undef DEFINE_XDP_CTX_POINTER

static __always_inline int xdp_get_meta(struct xdp_md *ctx, struct xdp_pipe_meta *meta) {
    void *data_meta = ctx_data_meta(ctx);
    void *data = ctx_data(ctx);
    if (data_meta + sizeof(*meta) > data) return -1;
    __builtin_memcpy(meta, data_meta, sizeof(*meta));
    return 0;
}

static __always_inline int xdp_set_meta(struct xdp_md *ctx, struct xdp_pipe_meta *meta) {
    int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret) return ret;
    void *data_meta = ctx_data_meta(ctx);
    void *data = ctx_data(ctx);
    if (data_meta + sizeof(*meta) > data) return -1;
    __builtin_memcpy(data_meta, meta, sizeof(*meta));
    return 0;
}

/* Stamp the chain id into the packet metadata, reusing any existing
 * meta area so repeated stamps never grow it. */
static __always_inline int xdp_stamp_chain_id(struct xdp_md *ctx, u32 chain_id) {
    struct xdp_pipe_meta meta = {};
    if (xdp_get_meta(ctx, &meta) != 0) {
        int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(meta));
        if (ret) return ret;
    }
    void *data_meta = ctx_data_meta(ctx);
    void *data = ctx_data(ctx);
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
    // chain the target's tc egress entry (tc_wan_egress_route) must tail into;
    // TC stamps it into skb->cb because xdp_md has no cb of its own.
    u16 link_chain_id;
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
    void *data_meta = ctx_data_meta(ctx);
    void *data = ctx_data(ctx);
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
                                                    u32 target_ifindex, u16 link_chain_id) {
    struct xdp_handoff_meta ho = {
        .magic = XDP_HANDOFF_TC_REDIRECT_MAGIC,
        .payload.tc_redirect = {.mark = mark,
                                .target_ifindex = target_ifindex,
                                .link_chain_id = link_chain_id},
    };
    return xdp_set_handoff_meta(ctx, &ho);
}

static __always_inline bool xdp_has_tc_redirect_meta(struct xdp_md *ctx) {
    void *data_meta = ctx_data_meta(ctx);
    void *data = ctx_data(ctx);
    if (data_meta + sizeof(struct xdp_handoff_meta) > data) return false;
    struct xdp_handoff_meta *ho = data_meta;
    return ho->magic == XDP_HANDOFF_TC_REDIRECT_MAGIC;
}

#endif /* __LD_PIPELINE_H_ */
