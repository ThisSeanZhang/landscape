#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "base/pppoe_def.h"
#include "map/wan_trie.h"

#define BENCH_ITERS 256
#define BENCH_SCAN_SLOTS 32 /* rust skel Default derive caps arrays at 32 */

struct bench_prefix_key {
    __u32 prefixlen; /* <= 64 */
    __u8 data[8];    /* network order */
};

/* One WAN prefix slot: mask is precomputed by the control plane, so the
 * data plane only pays AND + CMP per entry.
 */
struct bench_scan_entry {
    __be64 prefix_masked;
    __be64 mask;
    u32 root;
    u32 used;
};

/* Double-buffered scan table: readers pick a half via `cur` (aligned u32
 * load/store is atomic), writers fill the spare half then flip `cur`.
 */
struct bench_scan_tbl {
    u32 cur;
    u32 pad;
    struct bench_scan_entry tbl[2][BENCH_SCAN_SLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct bench_prefix_key));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 2048);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bench_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__be64));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 4096);
} bench_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} bench_sink SEC(".maps");

/* Array-carried scan table (single slot, whole-table update from userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct bench_scan_tbl));
    __uint(max_entries, 1);
} bench_scan_tbl_map SEC(".maps");

/* Arena-carried tables: the __arena globals land in the .addr_space.1 ELF
 * section; libbpf requires the ARENA map to be declared explicitly and sizes
 * it against the globals (max_entries is in pages; the trie table alone is
 * ~4.2MB => 1029 pages, rounded up for margin).
 * Userspace shares it via mmap(); BPF-side access is a plain load, no helper.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARENA_V);
    __uint(key_size, 0);
    __uint(value_size, 0);
    __uint(max_entries, 1032);
    __uint(map_flags, BPF_F_MMAPABLE);
} bench_arena SEC(".maps");

struct bench_scan_tbl __arena bench_arena_tbl;
struct wan_trie_tbl __arena bench_trie_tbl;

char LICENSE[] SEC("license") = "GPL";

static __always_inline int bench_extract_prefix64(struct xdp_md *ctx, __be64 *prefix64) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    if (eth->h_proto != ETH_IPV6) {
        return -1;
    }

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
    if ((void *)(ip6h + 1) > data_end) {
        return -1;
    }

    __builtin_memcpy(prefix64, &ip6h->daddr, sizeof(*prefix64));
    return 0;
}

static __always_inline void bench_write_sink(u64 acc) {
    u32 zero = 0;
    bpf_map_update_elem(&bench_sink, &zero, &acc, BPF_ANY);
}

SEC("xdp")
int bench_baseline(struct xdp_md *ctx) {
    __be64 prefix64 = 0;
    if (bench_extract_prefix64(ctx, &prefix64)) {
        return XDP_PASS;
    }

    u64 acc = (u64)prefix64;
    for (u32 i = 0; i < BENCH_ITERS; i++) {
        acc += (u64)(u32)i;
        __asm__ __volatile__("" : "+r"(acc)::"memory");
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

SEC("xdp")
int bench_hash(struct xdp_md *ctx) {
    __be64 key = 0;
    if (bench_extract_prefix64(ctx, &key)) {
        return XDP_PASS;
    }

    u64 acc = 0;
    for (u32 i = 0; i < BENCH_ITERS; i++) {
        u32 *v = bpf_map_lookup_elem(&bench_hash_map, &key);
        if (v) {
            acc += *v;
        }
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

SEC("xdp")
int bench_lpm(struct xdp_md *ctx) {
    __be64 prefix64 = 0;
    if (bench_extract_prefix64(ctx, &prefix64)) {
        return XDP_PASS;
    }

    struct bench_prefix_key key = {};
    key.prefixlen = 64;
    __builtin_memcpy(key.data, &prefix64, sizeof(prefix64));

    u64 acc = 0;
    for (u32 i = 0; i < BENCH_ITERS; i++) {
        u32 *v = bpf_map_lookup_elem(&bench_lpm_map, &key);
        if (v) {
            acc += *v;
        }
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

/* Scan a double-buffered table carried by a single-slot ARRAY map:
 * one helper call fetches the whole table, entries are direct loads.
 * Breaks on the first covering prefix, like the real dispatcher would.
 */
SEC("xdp")
int bench_array_scan(struct xdp_md *ctx) {
    __be64 prefix64 = 0;
    if (bench_extract_prefix64(ctx, &prefix64)) {
        return XDP_PASS;
    }

    u64 acc = 0;
    for (u32 iter = 0; iter < BENCH_ITERS; iter++) {
        u32 zero = 0;
        struct bench_scan_tbl *t = bpf_map_lookup_elem(&bench_scan_tbl_map, &zero);
        if (!t) {
            break;
        }

        struct bench_scan_entry *tab = t->tbl[t->cur & 1];
        for (u32 i = 0; i < BENCH_SCAN_SLOTS; i++) {
            struct bench_scan_entry *e = &tab[i];
            if (e->used && (prefix64 & e->mask) == e->prefix_masked) {
                acc += e->root;
                break;
            }
        }
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

/* Same algorithm and table shape, but carried by the arena: `bench_arena_tbl`
 * is an __arena global, so every access below is a plain direct load with no
 * helper call at all. This is the arena twin of bench_array_scan.
 */
SEC("xdp")
int bench_arena_scan(struct xdp_md *ctx) {
    __be64 prefix64 = 0;
    if (bench_extract_prefix64(ctx, &prefix64)) {
        return XDP_PASS;
    }

    u64 acc = 0;
    for (u32 iter = 0; iter < BENCH_ITERS; iter++) {
        struct bench_scan_entry __arena *tab = bench_arena_tbl.tbl[bench_arena_tbl.cur & 1];
        for (u32 i = 0; i < BENCH_SCAN_SLOTS; i++) {
            struct bench_scan_entry __arena *e = &tab[i];
            if (e->used && (prefix64 & e->mask) == e->prefix_masked) {
                acc += e->root;
                break;
            }
        }
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

/* Arena-carried stride-8 trie: the arena twin of the kernel's lpm_trie.
 * One wan_trie_resolve() call per iteration: at most 8 dependent child
 * loads plus one final vals load, no helper call / matchlen recompute / RCU.
 */
SEC("xdp")
int bench_arena_trie(struct xdp_md *ctx) {
    __be64 prefix64 = 0;
    if (bench_extract_prefix64(ctx, &prefix64)) {
        return XDP_PASS;
    }

    u64 acc = 0;
    for (u32 iter = 0; iter < BENCH_ITERS; iter++) {
        acc += wan_trie_resolve(&bench_trie_tbl, prefix64);
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

/* Tagged-namespace lookups through the same trie: IPv4 (5 hops for a /24)
 * and PPPoE (ifindex, session) (7 hops), both keyed behind the first tag
 * byte.
 */
static __always_inline int bench_extract_v4_daddr(struct xdp_md *ctx, __be32 *daddr) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end || eth->h_proto != ETH_IPV4) {
        return -1;
    }
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return -1;
    }
    *daddr = iph->daddr;
    return 0;
}

SEC("xdp")
int bench_trie_v4(struct xdp_md *ctx) {
    __be32 daddr = 0;
    if (bench_extract_v4_daddr(ctx, &daddr)) {
        return XDP_PASS;
    }

    u64 key = wan_trie_key_v4(daddr);
    u64 acc = 0;
    for (u32 iter = 0; iter < BENCH_ITERS; iter++) {
        acc += wan_trie_resolve(&bench_trie_tbl, key);
    }
    bench_write_sink(acc);
    return XDP_PASS;
}

SEC("xdp")
int bench_trie_ppp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end || eth->h_proto != ETH_P_PPP_SES) {
        return XDP_PASS;
    }
    struct pppoe_header *pppoe = (struct pppoe_header *)(eth + 1);
    if ((void *)(pppoe + 1) > data_end) {
        return XDP_PASS;
    }

    u64 key = wan_trie_key_ppp(ctx->ingress_ifindex, pppoe->session_id);
    u64 acc = 0;
    for (u32 iter = 0; iter < BENCH_ITERS; iter++) {
        acc += wan_trie_resolve(&bench_trie_tbl, key);
    }
    bench_write_sink(acc);
    return XDP_PASS;
}
