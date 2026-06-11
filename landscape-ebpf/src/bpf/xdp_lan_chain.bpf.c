#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
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
int xdp_lan_chain_root(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_root] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_root] target_ifindex=0");
        return XDP_PASS;
    }

    bpf_tail_call(ctx, &root_next_stage, 0);
    bpf_tail_call(ctx, &xdp_pipe_exits_lan, 0);

    bpf_printk("[lan_root] all tailcalls failed");
    return XDP_PASS;
}

SEC("xdp")
int xdp_lan_chain_exit(struct xdp_md *ctx) {
    struct xdp_pipe_meta meta = {};

    if (xdp_get_meta(ctx, &meta) != 0) {
        bpf_printk("[lan_exit] no meta");
        return XDP_PASS;
    }

    if (meta.target_ifindex == 0) {
        bpf_printk("[lan_exit] target_ifindex=0");
        return XDP_PASS;
    }

    // eth = data;
    // if ((void *)(eth + 1) > data_end) goto redirect;

    // if (eth->h_proto == ETH_IPV4) {
    //     iph = (struct iphdr *)(eth + 1);
    //     if ((void *)(iph + 1) > data_end) goto redirect;
    //     bpf_printk("[lan_exit] IPv4 saddr=%pI4 daddr=%pI4 smac=%pM dmac=%pM", &iph->saddr,
    //                &iph->daddr, eth->h_source, eth->h_dest);
    // }

redirect:
    // bpf_printk("[lan_exit] redirect to ifidx=%u", meta.target_ifindex);
    return bpf_redirect(meta.target_ifindex, 0);
}
