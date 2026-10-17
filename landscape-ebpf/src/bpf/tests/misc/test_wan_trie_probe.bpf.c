// Differential probe for the BPF-side `wan_trie` reader (`map/wan_trie.h`):
// the Rust test publishes the entry set into this program's arena through
// the mmap, then replays its case matrix via BPF_PROG_TEST_RUN and compares
// the returned root against the userspace `reference_lpm` — proving the C
// `wan_trie_resolve` walk and the `wan_trie_key_v4/ppp` layouts agree
// with the Rust builder, on a real kernel.
//
// Packet layout — every multi-byte payload field is in NETWORK byte order,
// exactly as it sits on the wire (payload byte j is trie key byte j):
//   [0]     mode: 0 raw 8-byte key, 1 ipv4 daddr, 2 pppoe (ifindex, session)
//   [1..8]  padding
//   [8..16] payload
//
// Returns the resolved dispatch root (0 = miss), or 0xFFFFFFFF when the
// request itself is malformed (short packet / unknown mode).
//
// Also hosts the sink pairs used by the xdp_wan_intro /
// tc_wan_ingress_intro dispatch tests.

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "map/wan_trie.h"

#define PROBE_BAD_KEY 0xFFFFFFFFu

WAN_TRIE_DECLARE(wan_trie_arena, wan_trie_tbl);

SEC("xdp")
int test_wan_trie_probe(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if ((void *)(data + 16) > data_end) {
        return PROBE_BAD_KEY;
    }

    u8 mode = *(u8 *)data;
    u64 key = 0;
    __builtin_memcpy(&key, data + 8, 8);

    switch (mode) {
    case 0:
        break;
    case 1: {
        __be32 daddr;
        __builtin_memcpy(&daddr, data + 8, 4);
        key = wan_trie_key_v4(daddr);
        break;
    }
    case 2: {
        __be32 ifindex_be;
        __be16 session;
        __builtin_memcpy(&ifindex_be, data + 8, 4);
        __builtin_memcpy(&session, data + 12, 2);
        key = wan_trie_key_ppp(bpf_ntohl(ifindex_be), session);
        break;
    }
    default:
        return PROBE_BAD_KEY;
    }

    return wan_trie_resolve(&wan_trie_tbl, key);
}

/* Sink A for chain-root slot assertions: flips packet byte 0. */
SEC("xdp")
int test_xdp_sink_a(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if ((void *)(data + 1) > data_end) {
        return XDP_DROP;
    }
    *(u8 *)data ^= 0xff;
    return XDP_PASS;
}

/* Sink B (distinct flip byte): lets one test tell two roots apart. */
SEC("xdp")
int test_xdp_sink_b(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if ((void *)(data + 2) > data_end) {
        return XDP_DROP;
    }
    *(u8 *)(data + 1) ^= 0xff;
    return XDP_PASS;
}

SEC("tc/ingress")
int test_tc_sink_a(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if ((void *)(data + 1) > data_end) {
        return TC_ACT_SHOT;
    }
    *(u8 *)data ^= 0xff;
    return TC_ACT_OK;
}

SEC("tc/ingress")
int test_tc_sink_b(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if ((void *)(data + 2) > data_end) {
        return TC_ACT_SHOT;
    }
    *(u8 *)(data + 1) ^= 0xff;
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
