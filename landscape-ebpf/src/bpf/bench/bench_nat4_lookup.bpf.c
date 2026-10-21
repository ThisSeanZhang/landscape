/* P0 bench: NAT4 per-packet lookup cost — current HASH-map choreography vs
 * the arena-native design (arena_nat4_design.md §6 P0-B).
 *
 * All variants model the DYNAMIC-flow hot paths with production-faithful
 * map shapes and key/value sizes:
 *
 *  - baseline:        packet extract only
 *  - hash_egress:     today's egress steady state = 2 static lookups (miss,
 *                     exact + wildcard) + egress dyn hit + ingress dyn
 *                     cross-check hit + timer map hit + 2 atomic counter
 *                     adds on the timer value
 *  - hash_ingress:    today's ingress steady state = timer hit + ingress
 *                     dyn hit + 2 atomic adds
 *  - hash_create:     today's per-new-flow cost = port queue pop + static
 *                     reservation check + 2x update(NOEXIST) + timer
 *                     update + lookup + timer_init/set_callback/start,
 *                     then the symmetric teardown (deletes + queue push)
 *  - arena_egress:    design's egress steady state = hash mix + idx probe
 *                     (tag + gen) + session field reads + last_used store +
 *                     2 atomic adds + non-ancestor endpoint line read
 *  - arena_ingress:   design's ingress steady state = hash mix + idx probe
 *                     + reads + last_used + 2 atomic adds
 *  - arena_create:    design's per-new-flow cost = bitmap CAS + endpoint
 *                     freelist pop + session freelist pop + init stores +
 *                     2 idx-slot CAS claims, then symmetric teardown
 *
 * Programs are single-shot: the driver runs each one via BPF_PROG_TEST_RUN
 * with kernel-side `repeat` batching and reads the kernel-reported per-run
 * average (no in-program loop → no verifier bounded-loop pressure; same
 * methodology as bench_skb_read). Every run folds its per-run value into
 * the accumulating sink map, so `warmup_batches * repeat * per_run` proves
 * from Rust that every single run hit the lookup under test.
 */
#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "base/landscape.h"
#include "map/arena.h"

#define BENCH_IDX_SLOTS 512 /* power of two */
#define BENCH_IDX_MASK (BENCH_IDX_SLOTS - 1)
#define BENCH_POOL 512
#define BENCH_EPS 128
#define BENCH_BITMAP_WORDS 2 /* 128 ports */
#define BENCH_EPSILON 0x9E3779B97F4A7C15ULL
#define BENCH_ST_N 8192          /* static entries (design §4.4 per half) */
#define BENCH_ST_IDX_SLOTS 16384 /* α = 0.5 for BENCH_ST_N */
#define BENCH_ST_IDX_MASK (BENCH_ST_IDX_SLOTS - 1)

/* ── Production-shaped HASH maps ─────────────────────────────────────── */

struct bench_map_key8 { /* nat4_mapping_key shape */
    __u8 gress;
    __u8 l4proto;
    __u16 from_port;
    __u32 from_addr;
};

struct bench_static_value {
    __u32 addr;
    __u16 port;
    __u16 _pad;
};

struct bench_egress_value { /* nat4_egress_mapping_value_v3 shape (16B) */
    __u32 addr;
    __u16 port;
    __u16 trigger_port;
    __u32 trigger_addr;
    __u8 is_allow_reuse;
    __u8 _pad[3];
};

struct bench_ingress_value { /* nat4_mapping_value_v3 shape (24B) */
    __u64 state_ref;
    __u32 addr;
    __u32 trigger_addr;
    __u16 port;
    __u16 trigger_port;
    __u16 generation;
    __u8 _pad;
    __u8 is_allow_reuse;
};

struct bench_timer_key { /* nat4_timer_key shape (16B: addrs first, ports last) */
    __u8 l4proto;
    __u8 _pad[3];
    __u32 src_addr;
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
};

struct bench_timer_value { /* nat4_timer_value_v3 shape (~104B, NO_PREALLOC) */
    __u64 status;
    __u64 client_status;
    __u64 server_status;
    __u32 client_addr;
    __u16 client_port;
    __u8 is_static;
    __u8 gress;
    __u16 generation_snapshot;
    __u16 _pad0;
    __u64 create_time;
    __u64 flow_id;
    __u64 ingress_bytes;
    __u64 ingress_packets;
    __u64 egress_bytes;
    __u64 egress_packets;
    __u32 cpu_id;
    __u32 ifindex;
    struct bpf_timer timer;
    __u8 __pad_tail[8];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bench_map_key8);
    __type(value, struct bench_static_value);
    __uint(max_entries, 64);
} bench_static_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bench_map_key8);
    __type(value, struct bench_egress_value);
    __uint(max_entries, 64);
} bench_egress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bench_map_key8);
    __type(value, struct bench_ingress_value);
    __uint(max_entries, 64);
} bench_ingress_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bench_timer_key);
    __type(value, struct bench_timer_value);
    __uint(max_entries, 64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bench_timer_map SEC(".maps");

struct bench_port_item { /* nat4_port_queue_value_v3 shape */
    __u16 port;
    __u16 last_generation;
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(key_size, 0);
    __type(value, struct bench_port_item);
    __uint(max_entries, 64);
} bench_port_queue SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} bench_sink SEC(".maps");

/* ── Arena image (the design's structures, bench-sized) ─────────────── */

struct bench_session {
    __u64 state_word;
    __u64 last_used;
    __u64 in_bytes;
    __u64 in_packets;
    __u64 out_bytes;
    __u64 out_packets;
    __u32 client_ip;
    __u32 peer_ip;
    __u32 nat_ip;
    __u32 ep_idx;
    __u32 gen;
    __u32 ep_gen;
    __u16 client_port;
    __u16 peer_port;
    __u16 nat_port;
    __u8 l4proto;
    __u8 flags; /* bit0: is_ancestor, bit1: is_static */
    __u16 _pad;
};

struct bench_endpoint {
    __u64 state_ref; /* {state:8|refcnt:56} like today */
    __u32 trigger_ip;
    __u16 trigger_port;
    __u16 nat_port;
    __u8 allow_reuse;
    __u8 gen;
    __u16 _pad;
};

struct bench_idx_slot {
    __u64 tag; /* hash >> 48; 0 = empty */
    __u32 sid;
    __u32 gen;
};

/* ── static NAT lookup evaluation set (§4.4) ───────────────────────────
 * Ingress-static shape: key = (proto, wan_port). Today this is ONE wildcard
 * HASH lookup (nat4_st_ingress_lookup). Arena candidates: binary search
 * over the sorted range table (§4.4 as written), an open-addressed idx
 * probe (the session-idx primitive reused), and a full port-space direct
 * array (space-for-time). */

struct bench_st_entry { /* §4.4 range+proto storage format (16B) */
    __u16 port_lo;
    __u16 port_hi;
    __u16 protos; /* bit0 tcp */
    __u16 _pad;
    __u32 lan_addr;
    __u16 lan_port;
    __u16 _pad2;
};

struct bench_st_idx_slot { /* 16B, same primitive as bench_idx_slot */
    __u64 tag;             /* hash >> 48; 0 = empty */
    __u32 ent;             /* index into st_table */
    __u32 _pad;
};

struct bench_arena_tbl {
    /* header-ish (heads are u64: BPF cmpxchg is 64-bit only, and the extra
     * bits double as an ABA tag) */
    __u64 session_free_head;
    __u64 endpoint_free_head;
    __u32 bitmap_cursor;
    __u32 _pad0;
    __u64 bitmap[BENCH_BITMAP_WORDS];
    __u32 session_next[BENCH_POOL]; /* intrusive freelist */
    __u32 endpoint_next[BENCH_EPS];
    struct bench_idx_slot idx_egress[BENCH_IDX_SLOTS];
    struct bench_idx_slot idx_ingress[BENCH_IDX_SLOTS];
    struct bench_session pool[BENCH_POOL];
    struct bench_endpoint eps[BENCH_EPS];
    struct bench_st_entry st_table[BENCH_ST_N];
    struct bench_st_idx_slot st_idx[BENCH_ST_IDX_SLOTS];
    __u64 st_direct[65536]; /* {valid:1|protos:8|lan_port:16|lan_addr:32} */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARENA_V);
    __uint(key_size, 0);
    __uint(value_size, 0);
    /* ~958 KiB image + margin */
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_MMAPABLE);
} bench_arena SEC(".maps");

struct bench_arena_tbl __arena_global bench_tbl;

char LICENSE[] SEC("license") = "GPL";

/* ── shared helpers ──────────────────────────────────────────────────── */

static __always_inline int bench_extract(struct xdp_md *ctx, __u32 *saddr, __u32 *daddr,
                                         __u16 *sport, __u16 *dport) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != ETH_IPV4) {
        return -1;
    }
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_TCP) {
        return -1;
    }
    struct tcphdr *th = (void *)iph + (iph->ihl << 2);
    if ((void *)(th + 1) > data_end) {
        return -1;
    }
    *saddr = iph->saddr;
    *daddr = iph->daddr;
    *sport = th->source;
    *dport = th->dest;
    return 0;
}

/* Accumulating sink: every test_run folds its per-run value in, so the
 * driver can prove all `repeat` runs hit (runs are kernel-serialized). */
static __always_inline void bench_sink_add(u64 add) {
    u32 zero = 0;
    u64 *old = bpf_map_lookup_elem(&bench_sink, &zero);
    u64 v = old ? *old : 0;
    v += add;
    bpf_map_update_elem(&bench_sink, &zero, &v, BPF_ANY);
}

static __always_inline u64 bench_mix64(u64 x) {
    x ^= x >> 33;
    x *= BENCH_EPSILON;
    x ^= x >> 29;
    x *= BENCH_EPSILON;
    x ^= x >> 32;
    return x;
}

/* Five-tuple (v4) → single 64-bit hash. Model of the design's probe key. */
static __always_inline u64 bench_flow_hash(u32 saddr, u32 daddr, u16 sport, u16 dport) {
    u64 x = ((__u64)saddr << 32) | daddr;
    u64 y = ((__u64)sport << 48) | ((__u64)dport << 32) | IPPROTO_TCP;
    return bench_mix64(x ^ bench_mix64(y));
}

/* ── baseline ────────────────────────────────────────────────────────── */

SEC("xdp")
int bench_baseline(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }
    bench_sink_add((__u64)saddr + daddr + sport + dport);
    return XDP_PASS;
}

/* ── today's HASH choreography ───────────────────────────────────────── */

SEC("xdp")
int bench_hash_egress(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    struct bench_map_key8 st_key = {
        .gress = 1,
        .l4proto = IPPROTO_TCP,
        .from_port = sport,
        .from_addr = saddr,
    };
    struct bench_timer_key t_key = {
        .l4proto = IPPROTO_TCP,
        .src_addr = daddr,
        .dst_addr = 0xAC100001,
        .src_port = dport,
        .dst_port = 40000,
    };

    u64 acc = 0;
    /* nat4_st_egress_lookup: exact then wildcard (both miss for a
     * dynamic flow) */
    (void)bpf_map_lookup_elem(&bench_static_map, &st_key);
    st_key.from_addr = 0;
    (void)bpf_map_lookup_elem(&bench_static_map, &st_key);

    /* dyn egress hit + dyn ingress cross-check hit */
    struct bench_map_key8 ek = {1, IPPROTO_TCP, sport, saddr};
    struct bench_egress_value *ev = bpf_map_lookup_elem(&bench_egress_map, &ek);
    struct bench_map_key8 ik = {0, IPPROTO_TCP, 0, 0};
    if (ev) {
        ik.from_port = ev->port;
        ik.from_addr = ev->addr;
        struct bench_ingress_value *iv = bpf_map_lookup_elem(&bench_ingress_map, &ik);
        if (iv) {
            if (iv->addr == saddr && iv->port == sport) {
                acc += ev->port + (ev->is_allow_reuse ? 0 : (ev->trigger_addr == daddr));
            }
        }
    }

    /* timer map hit + counter adds */
    struct bench_timer_value *tv = bpf_map_lookup_elem(&bench_timer_map, &t_key);
    if (tv) {
        __sync_fetch_and_add(&tv->egress_bytes, 64);
        __sync_fetch_and_add(&tv->egress_packets, 1);
        acc += tv->client_port;
    }

    bench_sink_add(acc);
    return XDP_PASS;
}

SEC("xdp")
int bench_hash_ingress(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    struct bench_timer_key t_key = {
        .l4proto = IPPROTO_TCP,
        .src_addr = saddr,
        .dst_addr = daddr,
        .src_port = sport,
        .dst_port = dport,
    };
    struct bench_map_key8 ik = {0, IPPROTO_TCP, dport, daddr};

    u64 acc = 0;
    struct bench_timer_value *tv = bpf_map_lookup_elem(&bench_timer_map, &t_key);
    if (tv) {
        __sync_fetch_and_add(&tv->ingress_bytes, 64);
        __sync_fetch_and_add(&tv->ingress_packets, 1);
        acc += tv->client_port;
    }
    struct bench_ingress_value *iv = bpf_map_lookup_elem(&bench_ingress_map, &ik);
    if (iv) {
        acc += iv->port;
    }

    bench_sink_add(acc);
    return XDP_PASS;
}

static int bench_timer_cb(void *map_, struct bench_timer_key *key,
                          struct bench_timer_value *value) {
    return 0;
}

SEC("xdp")
int bench_hash_create(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    struct bench_map_key8 ek = {1, IPPROTO_TCP, sport, saddr};
    struct bench_map_key8 ik = {0, IPPROTO_TCP, 0, 0};
    struct bench_timer_key t_key = {
        .l4proto = IPPROTO_TCP,
        .src_addr = daddr,
        .dst_addr = 0xAC100001,
        .src_port = dport,
        .dst_port = 0, /* filled from the popped port */
    };

    u64 acc = 0;
    /* nat4_alloc_port: pop until a non-reserved port */
    struct bench_port_item item = {};
    if (bpf_map_pop_elem(&bench_port_queue, &item) != 0) {
        acc += 11;
        bench_sink_add(acc);
        return XDP_PASS;
    }
    (void)bpf_map_lookup_elem(&bench_static_map,
                              &(struct bench_map_key8){0, IPPROTO_TCP, item.port, 0});

    /* nat4_insert_mappings */
    struct bench_egress_value ev = {
        .addr = 0xAC100001,
        .port = item.port,
    };
    struct bench_ingress_value iv = {};
    ik.from_port = item.port;
    ik.from_addr = ev.addr;
    if (bpf_map_update_elem(&bench_egress_map, &ek, &ev, BPF_NOEXIST) != 0) {
        (void)bpf_map_push_elem(&bench_port_queue, &item, BPF_EXIST);
        acc += 12;
        bench_sink_add(acc);
        return XDP_PASS;
    }
    if (bpf_map_update_elem(&bench_ingress_map, &ik, &iv, BPF_NOEXIST) != 0) {
        bpf_map_delete_elem(&bench_egress_map, &ek);
        (void)bpf_map_push_elem(&bench_port_queue, &item, BPF_EXIST);
        acc += 13;
        bench_sink_add(acc);
        return XDP_PASS;
    }

    /* nat4_insert_ct + timer trio */
    t_key.dst_port = item.port;
    struct bench_timer_value tv = {};
    if (bpf_map_update_elem(&bench_timer_map, &t_key, &tv, BPF_NOEXIST) != 0) {
        acc += 14;
        bench_sink_add(acc);
        return XDP_PASS;
    }
    struct bench_timer_value *tvp = bpf_map_lookup_elem(&bench_timer_map, &t_key);
    if (tvp) {
        if (bpf_timer_init(&tvp->timer, &bench_timer_map, CLOCK_MONOTONIC) == 0 &&
            bpf_timer_set_callback(&tvp->timer, bench_timer_cb) == 0) {
            (void)bpf_timer_start(&tvp->timer, 5000000000ULL, 0);
        }
        acc += 1; /* success marker: sink == runs proves every roundtrip */
    }

    /* teardown (timer callback DELETE path equivalent, inline) */
    bpf_map_delete_elem(&bench_timer_map, &t_key);
    bpf_map_delete_elem(&bench_egress_map, &ek);
    bpf_map_delete_elem(&bench_ingress_map, &ik);
    (void)bpf_map_push_elem(&bench_port_queue, &item, BPF_EXIST);

    bench_sink_add(acc);
    return XDP_PASS;
}

/* ── arena-native paths (the design) ─────────────────────────────────── */

/* Steady-state egress: one idx probe + session line + endpoint line
 * (non-ancestor) + last_used + counter adds. */
SEC("xdp")
int bench_arena_egress(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    u64 h = bench_flow_hash(saddr, daddr, sport, dport);
    u64 tag = h >> 48;
    u32 slot0 = h & BENCH_IDX_MASK;
    u64 now = bpf_ktime_get_ns();

    u64 acc = 0;
    struct bench_idx_slot __arena *s = &bench_tbl.idx_egress[slot0];
    if (s->tag == tag) {
        u32 sid = s->sid;
        struct bench_session __arena *sess = &bench_tbl.pool[sid];
        if (sess->gen == s->gen) {
            acc += sess->nat_port;
            u64 sw = sess->state_word; /* advance check (steady: no CAS) */
            acc += (sw == 0) ? 1 : 0;
            sess->last_used = now;
            __sync_fetch_and_add(&sess->out_bytes, 64);
            __sync_fetch_and_add(&sess->out_packets, 1);
            if (!(sess->flags & 1)) { /* non-ancestor: policy line read */
                struct bench_endpoint __arena *ep = &bench_tbl.eps[sess->ep_idx];
                acc += ep->allow_reuse;
            }
        }
    }

    bench_sink_add(acc);
    return XDP_PASS;
}

SEC("xdp")
int bench_arena_ingress(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    u64 h = bench_flow_hash(daddr, saddr, dport, sport); /* wan-side view */
    u64 tag = h >> 48;
    u32 slot0 = h & BENCH_IDX_MASK;
    u64 now = bpf_ktime_get_ns();

    u64 acc = 0;
    struct bench_idx_slot __arena *s = &bench_tbl.idx_ingress[slot0];
    if (s->tag == tag) {
        struct bench_session __arena *sess = &bench_tbl.pool[s->sid];
        if (sess->gen == s->gen) {
            acc += sess->client_port;
            sess->last_used = now;
            __sync_fetch_and_add(&sess->in_bytes, 64);
            __sync_fetch_and_add(&sess->in_packets, 1);
        }
    }

    bench_sink_add(acc);
    return XDP_PASS;
}

/* Lock-free freelist pop on an arena intrusive list (design §4.6). BPF
 * cmpxchg is 64-bit only, so heads are u64 (low 32 bits = index). */
static __always_inline int bench_freelist_pop(__u64 __arena *head, __u32 __arena *nexts,
                                              __u32 limit) {
#pragma unroll
    for (int i = 0; i < 8; i++) {
        __u64 old = *(volatile __u64 __arena *)head;
        if ((__u32)old >= limit) {
            return -1;
        }
        __u64 next = nexts[(u32)old];
        if (__sync_val_compare_and_swap(head, old, next) == old) {
            return (int)(u32)old;
        }
    }
    return -1;
}

static __always_inline void bench_freelist_push(__u64 __arena *head, __u32 __arena *nexts,
                                                __u32 idx) {
#pragma unroll
    for (int i = 0; i < 8; i++) {
        __u64 old = *(volatile __u64 __arena *)head;
        nexts[idx] = (__u32)old;
        if (__sync_val_compare_and_swap(head, old, idx) == old) {
            return;
        }
    }
}

/* Bitmap port alloc: monotone cursor + CAS claim (design §4.5). */
static __always_inline int bench_bitmap_alloc(void) {
    for (u32 w = 0; w < BENCH_BITMAP_WORDS; w++) {
        __u32 wi = (bench_tbl.bitmap_cursor + w) & (BENCH_BITMAP_WORDS - 1);
        for (u32 b = 0; b < 64; b++) {
            __u64 mask = 1ULL << b;
            __u64 old = *(volatile __u64 __arena *)&bench_tbl.bitmap[wi];
            if (old & mask) {
                continue;
            }
            if (__sync_val_compare_and_swap(&bench_tbl.bitmap[wi], old, old | mask) == old) {
                bench_tbl.bitmap_cursor = (wi + 1) & (BENCH_BITMAP_WORDS - 1);
                return wi * 64 + b;
            }
        }
    }
    return -1;
}

static __always_inline void bench_bitmap_clear(int port) {
    __u64 __arena *w = &bench_tbl.bitmap[port / 64];
    __sync_fetch_and_and(w, ~(1ULL << (port % 64)));
}

/* Session/endpoint init take the member address as a raw u64 and pin it
 * through the asm cast above: plain __arena GEPs get re-materialized by
 * clang under pressure, the asm pin cannot be. */
static __noinline void bench_sess_init(u64 sess_addr, u64 sid_port, u64 addrs, u64 ports_ep,
                                       u64 now) {
    struct bench_session *sess = (struct bench_session *)sess_addr;
    ARENA_CAST_KERN(sess);
    u32 port = sid_port >> 32;
    sess->state_word = 0;
    sess->client_ip = (u32)addrs;
    sess->peer_ip = addrs >> 32;
    sess->nat_ip = 0xAC100001;
    sess->nat_port = 32768 + port;
    sess->client_port = (u16)ports_ep;
    sess->peer_port = (u16)(ports_ep >> 16);
    sess->l4proto = IPPROTO_TCP;
    sess->ep_idx = (u32)(ports_ep >> 32);
    sess->ep_gen = 1;
    sess->gen = 1;
    sess->in_bytes = 0;
    sess->in_packets = 0;
    sess->out_bytes = 0;
    sess->out_packets = 0;
    sess->last_used = now;
}

static __noinline void bench_ep_init(u64 ep_addr, u32 daddr, u32 dport_nat) {
    struct bench_endpoint *e = (struct bench_endpoint *)ep_addr;
    ARENA_CAST_KERN(e);
    e->state_ref = (1ULL << 56) | 1;
    e->trigger_ip = daddr;
    e->trigger_port = (u16)dport_nat;
    e->nat_port = (u16)(dport_nat >> 16);
    e->allow_reuse = 1;
    e->gen = 1;
}

SEC("xdp")
int bench_arena_create(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }

    u64 h = bench_flow_hash(saddr, daddr, sport, dport);
    u64 h2 = bench_flow_hash(daddr, saddr, dport, sport);
    u64 now = bpf_ktime_get_ns();

    u64 acc = 0;
    /* endpoint + session claims */
    int ep = bench_freelist_pop(&bench_tbl.endpoint_free_head, bench_tbl.endpoint_next, BENCH_EPS);
    int sid = bench_freelist_pop(&bench_tbl.session_free_head, bench_tbl.session_next, BENCH_POOL);
    int port = bench_bitmap_alloc();
    if (ep < 0 || sid < 0 || port < 0) {
        acc += 21;
        bench_sink_add(acc);
        return XDP_PASS;
    }

    bench_sess_init((u64)&bench_tbl.pool[sid], ((u64)sid) | ((u64)port << 32),
                    ((u64)saddr) | ((u64)daddr << 32),
                    ((u64)sport) | ((u64)dport << 16) | ((u64)ep << 32), now);
    bench_ep_init((u64)&bench_tbl.eps[ep], daddr, dport | ((u64)(32768 + port) << 16));
    u16 nat_port = 32768 + port;

    /* both idx claims (fresh slot: CAS empty → {tag,sid,gen}) */
    struct bench_idx_slot __arena *s0 = &bench_tbl.idx_egress[h & BENCH_IDX_MASK];
    struct bench_idx_slot __arena *s1 = &bench_tbl.idx_ingress[h2 & BENCH_IDX_MASK];
    u64 empty0 = *(volatile u64 __arena *)&s0->tag;
    u64 empty1 = *(volatile u64 __arena *)&s1->tag;
    if (empty0 != 0 || empty1 != 0 || __sync_val_compare_and_swap(&s0->tag, 0, h >> 48) != 0 ||
        __sync_val_compare_and_swap(&s1->tag, 0, h2 >> 48) != 0) {
        /* slot occupied from a previous run that failed teardown */
        acc += 22;
        bench_freelist_push(&bench_tbl.session_free_head, bench_tbl.session_next, sid);
        bench_freelist_push(&bench_tbl.endpoint_free_head, bench_tbl.endpoint_next, ep);
        bench_bitmap_clear(port);
        bench_sink_add(acc);
        return XDP_PASS;
    }
    s0->sid = sid;
    s0->gen = 1;
    s1->sid = sid;
    s1->gen = 1;
    acc += nat_port;

    /* teardown */
    (void)__sync_val_compare_and_swap(&s0->tag, h >> 48, 0);
    (void)__sync_val_compare_and_swap(&s1->tag, h2 >> 48, 0);
    bench_freelist_push(&bench_tbl.session_free_head, bench_tbl.session_next, sid);
    bench_freelist_push(&bench_tbl.endpoint_free_head, bench_tbl.endpoint_next, ep);
    bench_bitmap_clear(port);

    bench_sink_add(acc);
    return XDP_PASS;
}

/* ── static NAT lookup primitives: the four candidates, head to head ───
 *
 * All use the ingress-static shape (proto=TCP, wan_port = packet dport) and
 * fold `lan_port` (777) into the sink on hit, so the driver proves every
 * run hit with the same expected value. */

/* today: ONE wildcard HASH lookup (nat4_st_ingress_lookup shape). */
SEC("xdp")
int bench_static_hash(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }
    struct bench_map_key8 k = {0, IPPROTO_TCP, dport, 0};
    u64 acc = 0;
    struct bench_static_value *v = bpf_map_lookup_elem(&bench_static_map, &k);
    if (v) {
        acc += v->port;
    }
    bench_sink_add(acc);
    return XDP_PASS;
}

/* asm-cast pins for the runtime-indexed static-section pointers. */
static __always_inline struct bench_st_entry *bench_st_at(u32 i) {
    struct bench_st_entry *e = (struct bench_st_entry *)(u64)&bench_tbl.st_table[i];
    ARENA_CAST_KERN(e);
    return e;
}

static __always_inline struct bench_st_idx_slot *bench_st_idx_at(u32 i) {
    struct bench_st_idx_slot *s = (struct bench_st_idx_slot *)(u64)&bench_tbl.st_idx[i];
    ARENA_CAST_KERN(s);
    return s;
}

static __always_inline u64 bench_st_direct_at(u16 port) {
    u64 *p = (u64 *)(u64)&bench_tbl.st_direct[port];
    ARENA_CAST_KERN(p);
    return *p;
}

/* §4.4 as written: sorted range table + binary search (≤13 bounded iters). */
SEC("xdp")
int bench_static_binsearch(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }
    u64 acc = 0;
    u32 lo = 0;
    u32 hi = BENCH_ST_N;
    for (int i = 0; i < 14; i++) {
        if (lo >= hi) {
            break;
        }
        u32 mid = (lo + hi) >> 1;
        struct bench_st_entry *e = bench_st_at(mid);
        if (dport < e->port_lo) {
            hi = mid;
            continue;
        }
        if (dport > e->port_hi) {
            lo = mid + 1;
            continue;
        }
        acc += e->lan_port;
        break;
    }
    bench_sink_add(acc);
    return XDP_PASS;
}

/* open-addressed idx probe: the session-idx primitive reused (α = 0.5). */
SEC("xdp")
int bench_static_idx(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }
    u64 h = bench_mix64(((u64)dport << 32) | IPPROTO_TCP);
    u64 tag = h >> 48;
    u32 slot0 = h & BENCH_ST_IDX_MASK;
    u64 acc = 0;
    for (u32 i = 0; i < 8; i++) {
        struct bench_st_idx_slot *sl = bench_st_idx_at((slot0 + i) & BENCH_ST_IDX_MASK);
        if (sl->tag == 0) {
            break; /* empty → miss */
        }
        if (sl->tag == tag) {
            struct bench_st_entry *e = bench_st_at(sl->ent);
            if (e->protos & 1) {
                acc += e->lan_port;
            }
            break;
        }
    }
    bench_sink_add(acc);
    return XDP_PASS;
}

/* full port-space direct array: ONE load, zero probing (space-for-time). */
SEC("xdp")
int bench_static_direct(struct xdp_md *ctx) {
    __u32 saddr = 0, daddr = 0;
    __u16 sport = 0, dport = 0;
    if (bench_extract(ctx, &saddr, &daddr, &sport, &dport)) {
        return XDP_PASS;
    }
    u64 v = bench_st_direct_at(dport);
    u64 acc = 0;
    if (v >> 63) {                 /* valid */
        acc += (v >> 32) & 0xffff; /* lan_port */
    }
    bench_sink_add(acc);
    return XDP_PASS;
}
