#ifndef __LD_MAP_WAN_TRIE_H__
#define __LD_MAP_WAN_TRIE_H__

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* libbpf 1.7's bpf_helpers.h does not ship the __arena macro yet */
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif

/* The pinned vmlinux.h predates BPF_MAP_TYPE_ARENA, so use its raw value;
 * libbpf-sys 1.7 only needs the number when parsing the ELF .maps section.
 */
#ifndef BPF_MAP_TYPE_ARENA_V
#define BPF_MAP_TYPE_ARENA_V 33
#endif

/* Node pool size per half. All programs (production and bench) use the
 * default 2048, i.e. a ~4.2MB arena per loaded program. To shrink it,
 * define WAN_TRIE_POOL_NODES before including this header AND keep
 * WAN_TRIE_POOL_NODES in src/maps/wan_trie/types.rs in sync — the
 * cast_arena_tbl size assert and the layout tests catch drift.
 */
#ifndef WAN_TRIE_POOL_NODES
#define WAN_TRIE_POOL_NODES 2048
#endif

/* Stride-8 (256-way) multibit trie over the first 64 bits of the IPv6
 * destination address, carried by an arena (`__arena` global).
 *
 * Layout invariants that keep the data-plane walk short and simple:
 * - Node position encodes the prefix: a node reached after k bytes covers
 *   the first k*8 bits, so byte-aligned prefixes need no per-node matchlen
 *   recompute (unlike the kernel's stride-1 lpm_trie).
 * - A node is a pure 256-way child table, exactly 1024B, so node addressing
 *   is `idx << 10`: no multiplies on the dependent path.
 * - Values live in a parallel `vals` array and are INHERITED at build time:
 *   vals[idx] is already the LPM answer for any dst reaching node idx, so
 *   the walk reads exactly one value, at the very end, off the critical path.
 * - Non-byte-aligned prefix lengths (/49../55, /57../63, ...) are supported
 *   through control-plane prefix expansion: a /plen = 8k+r prefix is stored
 *   as 2^(8-r) virtual byte-aligned entries at depth k+1 (<= 128 copies).
 *   Shorter prefixes are inserted first so longer ones overwrite: nesting
 *   keeps exact LPM semantics.
 *
 * child[] stores node_index + 1 (0 = absent); vals[] stores the dispatch
 * root (0 = miss). Arrays are chunked to <= 32 per dimension so the
 * generated rust skel's Default derive compiles; both sides address them
 * flat (BPF via pointer arithmetic, Rust via index helpers).
 *
 * Readers pick a half via `cur` (aligned u32 load/store is atomic); the
 * control plane fills the spare half, then flips `cur` last.
 */
struct wan_trie_node {
    u32 child[8][32];
};

struct wan_trie_half {
    u32 node_cnt;
    struct wan_trie_node nodes[2][32][32];
    u32 vals[2][32][32];
};

struct wan_trie_tbl {
    u32 cur;
    u32 pad;
    struct wan_trie_half halves[2];
};

/* One lookup: at most 8 dependent child loads plus one final vals load.
 * `dst64` is the raw first 8 bytes of daddr as a u64 register (the value
 * BPF gets from memcpy; on x86 packet byte j sits in bits 8j..8j+7).
 */
static __always_inline u32 wan_trie_resolve(struct wan_trie_tbl __arena *tbl, u64 dst64) {
    struct wan_trie_half __arena *h = &tbl->halves[tbl->cur & 1];
    struct wan_trie_node __arena *pool = &h->nodes[0][0][0];
    u32 __arena *vals = &h->vals[0][0][0];

    /* Pre-extract the 8 key bytes: independent shifts, off the chain. */
    u8 b[8];
#pragma unroll
    for (u32 j = 0; j < 8; j++) {
        b[j] = (dst64 >> (8 * j)) & 0xff;
    }

    u32 idx = 0;
    struct wan_trie_node __arena *node = pool;
#pragma unroll
    for (u32 k = 0; k < 8; k++) {
        u32 c = node->child[b[k] >> 5][b[k] & 31];
        if (c == 0 || c > WAN_TRIE_POOL_NODES) {
            break;
        }
        idx = c - 1;
        node = pool + idx; /* idx * 1024 = idx << 10 */
    }

    /* vals[idx] already carries the longest covering prefix's root. */
    return vals[idx];
}

/* Namespace tags for non-IPv6 keys: the first key byte. All live in
 * IETF-reserved IPv6 space (0000::/8, 0300::/8), so they can never
 * collide with a real IPv6 prefix; the Rust builder additionally
 * rejects v6 entries whose masked byte0 is below 0x04.  (The 0x02 tag
 * once keyed an ifindex namespace used as an ingress fallback; it is
 * retired — dispatch is chain-keyed and trie-published only.)
 */
#define WAN_TRIE_TAG_V4 0x00
#define WAN_TRIE_TAG_PPP 0x03

/* Key layout, in walk order (resolve reads key byte j from bits 8j..8j+7,
 * i.e. packet byte j sits in the LOW end of the u64 register on LE):
 *   IPv6  [ a0 a1 a2 a3 a4 a5 a6 a7 ]    plen 0..64,  up to 8 hops
 *   IPv4  [ 00 | a  b  c  d | 0  0  0 ]  plen 8+n,    up to 5 hops
 *   ppp   [ 03 | sh sl | 0  0  0  0  0 ]  plen 24,    3 hops
 *
 * A big-endian header field loaded into a register already packs its
 * packet bytes ascending (byte j at bits 8j), so it just shifts up by one
 * byte behind the tag.
 */
static __always_inline u64 wan_trie_key_v4(__be32 daddr) {
    return WAN_TRIE_TAG_V4 | ((u64)daddr << 8);
}

static __always_inline u64 wan_trie_key_ppp(__be16 session) {
    return WAN_TRIE_TAG_PPP | ((u64)session << 8);
}

/* Pages needed for the trie table (all sizes in bytes, rounded up). */
#define WAN_TRIE_ARENA_PAGES ((sizeof(struct wan_trie_tbl) + 4095) / 4096)

/* Convenience declaration for programs whose arena carries ONLY the trie:
 * declares the ARENA map and the __arena global. A program that shares one
 * arena map between several tables (e.g. the benchmark) declares its own
 * map once and just defines `struct wan_trie_tbl __arena <name>;` instead.
 */
#define WAN_TRIE_DECLARE(map_name, var_name)                                                       \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_ARENA_V);                                                        \
        __uint(key_size, 0);                                                                       \
        __uint(value_size, 0);                                                                     \
        __uint(max_entries, WAN_TRIE_ARENA_PAGES);                                                 \
        __uint(map_flags, BPF_F_MMAPABLE);                                                         \
    } map_name SEC(".maps");                                                                       \
    struct wan_trie_tbl __arena var_name;

#endif /* __LD_MAP_WAN_TRIE_H__ */
