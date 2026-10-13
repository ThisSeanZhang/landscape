#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "chain/xdp_meta.h"
#include "chain/redirect_able.h"
#include "chain/xdp_wan_maps.h"
#include "chain/xdp_lan_maps.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} root_next_stage SEC(".maps");

SEC("xdp")
int xdp_lan_root(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_root] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_root] target_ifindex=0");
        return XDP_PASS;
    }

    bpf_tail_call_static(ctx, &root_next_stage, 0);
    XDP_FROM_LAN_CHAIN_EXIT(ctx);

    bpf_printk("[lan_root] all tailcalls failed");
    return XDP_PASS;
}
