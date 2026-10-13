#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "base/landscape.h"
#include "chain/xdp_meta.h"
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
int xdp_wan_root(struct xdp_md *ctx) {
    bpf_tail_call_static(ctx, &root_next_stage, 0);
    XDP_FROM_WAN_CHAIN_EXIT(ctx);
    return XDP_PASS;
}
