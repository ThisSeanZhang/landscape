#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_test_dummy(struct xdp_md *ctx) {
    u32 pkt_len = (u32)((long)ctx->data_end - (long)ctx->data);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("[dump] recv pkt_len=%u (short)", pkt_len);
    } else {
        bpf_printk("[dump] recv pkt_len=%u eth=%04x", pkt_len, bpf_ntohs(eth->h_proto));
    }
    return XDP_PASS;
}
