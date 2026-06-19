#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "landscape.h"
#include "scanner/xdp_common.h"
#include "scanner/xdp_scanner4.h"
#include "scanner/xdp_scanner6.h"

char LICENSE[] SEC("license") = "GPL";

struct xdp_scan_test_result {
    u8 scan_ret;
    u8 l3_proto;
    u8 _pad[2];
    struct scan_ipv4_idx v4;
    struct scan_ipv6_idx v6;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct xdp_scan_test_result);
} xdp_scan_test_map SEC(".maps");

SEC("xdp")
int xdp_test_scanner(struct xdp_md *ctx) {
    u32 key = 0;
    struct xdp_scan_test_result *result = bpf_map_lookup_elem(&xdp_scan_test_map, &key);
    if (!result) return XDP_PASS;

    __builtin_memset(result, 0, sizeof(*result));

    enum xdp_l3_proto proto = xdp_classify_l3(ctx);

    if (proto == XDP_L3_V4) {
        result->l3_proto = 4;
        result->scan_ret = (u8)xdp_scan_ipv4_full(ctx, sizeof(struct ethhdr), &result->v4);
    } else if (proto == XDP_L3_V6) {
        result->l3_proto = 6;
        result->scan_ret = (u8)xdp_scan_ipv6_full(ctx, sizeof(struct ethhdr), &result->v6);
    }

    return XDP_PASS;
}
