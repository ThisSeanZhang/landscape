#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "pipeline/pipeline.h"

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_test_redirect(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) == 0 && meta.target_ifindex != 0) {
        return bpf_redirect(meta.target_ifindex, 0);
    }

    return XDP_PASS;
}
