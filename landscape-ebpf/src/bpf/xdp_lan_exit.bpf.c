#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "chain/xdp_meta.h"

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_lan_exit(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_exit] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_exit] target_ifindex=0");
        return XDP_PASS;
    }

    return bpf_redirect(meta.target_ifindex, 0);
}
