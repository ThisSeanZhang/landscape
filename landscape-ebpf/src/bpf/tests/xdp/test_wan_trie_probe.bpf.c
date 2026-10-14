// Differential probe for the BPF-side `wan_trie` reader (`map/wan_trie.h`):
// the Rust test publishes the entry set into this program's arena through
// the mmap, then replays its case matrix via BPF_PROG_TEST_RUN and compares
// the returned root against the userspace `reference_lpm` — proving the C
// `wan_trie_resolve` walk and the `wan_trie_key_v4/ppp/ifx` layouts agree
// with the Rust builder, on a real kernel.
//
// Packet layout — every multi-byte payload field is in NETWORK byte order,
// exactly as it sits on the wire (payload byte j is trie key byte j):
//   [0]     mode: 0 raw 8-byte key, 1 ipv4 daddr, 2 pppoe session, 3 ifindex
//   [1..8]  padding
//   [8..16] payload
//
// Returns the resolved dispatch root (0 = miss), or 0xFFFFFFFF when the
// request itself is malformed (short packet / unknown mode).

#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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
        __be16 session;
        __builtin_memcpy(&session, data + 8, 2);
        key = wan_trie_key_ppp(session);
        break;
    }
    default:
        return PROBE_BAD_KEY;
    }

    return wan_trie_resolve(&wan_trie_tbl, key);
}

char LICENSE[] SEC("license") = "GPL";
