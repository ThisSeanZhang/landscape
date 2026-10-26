//! NAT4 per-packet cost: today's HASH-map choreography vs the arena-native
//! design (`redirect_server3/arena_nat4_design.md` §6 P0-B).
//!
//! Steady state (`_egress`/`_ingress`) and new-flow (`_create`) twins, all
//! with production-faithful map shapes. See the header comment of
//! `src/bpf/bench/bench_nat4_lookup.bpf.c` for what each variant models.
//!
//! Programs are single-shot: one syscall runs `REPEAT` kernel-side repeats
//! and reports the per-run average, and the accumulating sink proves every
//! run hit (`warmup_batches * repeat * per_run`). Baseline subtraction
//! cancels the shared packet-parse and test-run machinery. Programs cannot
//! be interleaved across rounds (arena_create's teardown frees the idx slots
//! the steady-state twins claim), so each program is measured sequentially:
//! warmup+assert, then `TIMING_BATCHES` batch averages.
//!
//! Run with: `cargo test -p landscape-ebpf --lib --features bpf-test bench:: -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use super::bench_nat4_lookup::BenchNat4LookupSkelBuilder;
use super::bench_nat4_lookup::types;
use crate::tests::pkt::simple_ipv4_tcp;

const XDP_PASS: u32 = 2; // enum xdp_action: ABORTED=0, DROP=1, PASS=2

/// Kernel-side BPF_PROG_TEST_RUN batching: one syscall runs the program
/// this many times and reports the average per-run duration.
const REPEAT: u32 = 256;
const WARMUP_BATCHES: usize = 5;
const TIMING_BATCHES: usize = 50;

const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const DST: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
// simple_ipv4_tcp hardcodes sport 12345 → dport 443.
/// Register values as the BPF side sees them: a u16/u32 load of wire-order
/// (big-endian) bytes on a little-endian CPU, i.e. byte-swapped.
const SADDR: u32 = 0x0100_000A; // u32::from_le_bytes(SRC.octets())
const DADDR: u32 = 0x0101_0101; // u32::from_le_bytes(DST.octets())
const SPORT_REG: u16 = 14640; // u16::from_le_bytes((12345u16).to_be_bytes())
const DPORT_REG: u16 = 47873; // u16::from_le_bytes((443u16).to_be_bytes())
/// One baseline run folds saddr+daddr+sport+dport into the sink.
const BASELINE_PER_RUN: u64 = SADDR as u64 + DADDR as u64 + SPORT_REG as u64 + DPORT_REG as u64;

const IPPROTO_TCP: u8 = 6;
const NAT_IP: u32 = 0xAC100001;
const NAT_PORT: u16 = 40000; // invented values; both sides use them raw
const TIMER_CPORT: u16 = 5000;
const INGRESS_VPORT: u16 = 7777;
const SEEDED_PORT: u16 = 32768;

const IDX_MASK: usize = 511;

// Per-run sink values, pinned by the sink asserts below.
const HASH_EGRESS_PER_RUN: u64 = NAT_PORT as u64 + TIMER_CPORT as u64;
const HASH_INGRESS_PER_RUN: u64 = TIMER_CPORT as u64 + INGRESS_VPORT as u64;
const ARENA_EGRESS_PER_RUN: u64 = NAT_PORT as u64 + 1; // + endpoint allow_reuse
const ARENA_INGRESS_PER_RUN: u64 = SPORT_REG as u64;
const HASH_CREATE_PER_RUN: u64 = 1;
/// arena_create folds 32768 + port (<128) per run.
const ARENA_CREATE_MIN: u64 = 32768;
const ARENA_CREATE_MAX: u64 = 32768 + 127;

/* ── static NAT lookup evaluation set (ingress shape: (proto, wan_port)) ── */

const ST_LAN_PORT: u16 = 777; // folded into the sink on hit
const ST_LAN_ADDR: u32 = 0x0A00_0063; // raw, both sides agree
const ST_TABLE_N: usize = 8192;
const ST_IDX_MASK: usize = 16383; // 16384 slots, α = 0.5
const ST_PORT_STEP: u32 = 7; // distractor stride: 1024 + 7*i stays < 65535
const STATIC_PER_RUN: u64 = ST_LAN_PORT as u64;

/// Murmur-style finalizer, byte-identical to the BPF side.
fn mix64(mut x: u64) -> u64 {
    const EPSILON: u64 = 0x9E37_79B9_7F4A_7C15;
    x ^= x >> 33;
    x = x.wrapping_mul(EPSILON);
    x ^= x >> 29;
    x = x.wrapping_mul(EPSILON);
    x ^= x >> 32;
    x
}

fn flow_hash(saddr: u32, daddr: u32, sport: u16, dport: u16) -> u64 {
    let x = ((saddr as u64) << 32) | daddr as u64;
    let y = ((sport as u64) << 48) | ((dport as u64) << 32) | IPPROTO_TCP as u64;
    mix64(x ^ mix64(y))
}

/* ── key/value serializers (offsets pinned by the layout asserts below) ── */

fn ser_key8(gress: u8, port: u16, addr: u32) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = gress;
    k[1] = IPPROTO_TCP;
    k[2..4].copy_from_slice(&port.to_ne_bytes());
    k[4..8].copy_from_slice(&addr.to_ne_bytes());
    k
}

fn ser_timer_key(src_addr: u32, dst_addr: u32, src_port: u16, dst_port: u16) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[0] = IPPROTO_TCP;
    k[4..8].copy_from_slice(&src_addr.to_ne_bytes());
    k[8..12].copy_from_slice(&dst_addr.to_ne_bytes());
    k[12..14].copy_from_slice(&src_port.to_ne_bytes());
    k[14..16].copy_from_slice(&dst_port.to_ne_bytes());
    k
}

fn ser_egress_value(addr: u32, port: u16, is_allow_reuse: u8) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..4].copy_from_slice(&addr.to_ne_bytes());
    v[4..6].copy_from_slice(&port.to_ne_bytes());
    v[12] = is_allow_reuse;
    v
}

/// Ingress dyn value (24B): only `addr`/`port` are read by the bench progs.
fn ser_ingress_value(addr: u32, port: u16) -> [u8; 24] {
    let mut v = [0u8; 24];
    v[8..12].copy_from_slice(&addr.to_ne_bytes());
    v[16..18].copy_from_slice(&port.to_ne_bytes());
    v
}

fn ser_timer_value(client_port: u16) -> Vec<u8> {
    let mut v = vec![0u8; std::mem::size_of::<types::bench_timer_value>()];
    let off = std::mem::offset_of!(types::bench_timer_value, client_port);
    v[off..off + 2].copy_from_slice(&client_port.to_ne_bytes());
    v
}

/// Generated-skel layout pins: the serializers above are only valid if the
/// BPF structs landed exactly where we hardcode bytes.
fn assert_layouts() {
    use std::mem::{offset_of, size_of};
    assert_eq!(size_of::<types::bench_map_key8>(), 8);
    assert_eq!(offset_of!(types::bench_map_key8, from_port), 2);
    assert_eq!(offset_of!(types::bench_map_key8, from_addr), 4);
    assert_eq!(size_of::<types::bench_timer_key>(), 16);
    assert_eq!(offset_of!(types::bench_timer_key, src_addr), 4);
    assert_eq!(offset_of!(types::bench_timer_key, dst_addr), 8);
    assert_eq!(offset_of!(types::bench_timer_key, src_port), 12);
    assert_eq!(offset_of!(types::bench_timer_key, dst_port), 14);
    assert_eq!(size_of::<types::bench_egress_value>(), 16);
    assert_eq!(offset_of!(types::bench_egress_value, port), 4);
    assert_eq!(offset_of!(types::bench_egress_value, is_allow_reuse), 12);
    assert_eq!(size_of::<types::bench_ingress_value>(), 24);
    assert_eq!(offset_of!(types::bench_ingress_value, addr), 8);
    assert_eq!(offset_of!(types::bench_ingress_value, port), 16);
    assert_eq!(size_of::<types::bench_port_item>(), 4);
}

fn read_sink(map: &impl MapCore) -> u64 {
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        .expect("read bench_sink")
        .expect("bench_sink entry missing");
    u64::from_ne_bytes(raw.as_slice().try_into().unwrap())
}

fn zero_sink(map: &impl MapCore) {
    map.update(&0u32.to_ne_bytes(), &0u64.to_ne_bytes(), MapFlags::ANY).expect("zero bench_sink");
}

/// One batch: REPEAT kernel-side runs, returns the reported per-run
/// average duration in ns.
fn sample_batch(prog: &ProgramMut<'_>, packet: &[u8]) -> u128 {
    let out = prog
        .test_run(ProgramInput {
            data_in: Some(packet),
            repeat: REPEAT,
            ..Default::default()
        })
        .expect("test_run");
    assert_eq!(out.return_value, XDP_PASS, "prog did not return XDP_PASS");
    out.duration.as_nanos()
}

/// Correctness + warmup pass: zero the sink, run WARMUP_BATCHES batches,
/// then assert every single run folded `per_run` into the sink.
fn warmup_checked(prog: &ProgramMut<'_>, packet: &[u8], per_run: u64, sink: &impl MapCore) {
    zero_sink(sink);
    for _ in 0..WARMUP_BATCHES {
        sample_batch(prog, packet);
    }
    assert_eq!(
        read_sink(sink),
        (WARMUP_BATCHES as u64 * REPEAT as u64) * per_run,
        "sink proves not every run hit"
    );
}

/// Timing pass: TIMING_BATCHES batch averages → (min, median).
fn timing(prog: &ProgramMut<'_>, packet: &[u8]) -> (u128, u128) {
    let mut samples: Vec<u128> = Vec::with_capacity(TIMING_BATCHES);
    for _ in 0..TIMING_BATCHES {
        samples.push(sample_batch(prog, packet));
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn report(name: &str, (min, med): (u128, u128), (base_min, base_med): (u128, u128)) {
    let per_min = min.saturating_sub(base_min) as f64;
    let per_med = med.saturating_sub(base_med) as f64;
    println!("{name:<16} per-run(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

#[test]
#[ignore = "bench"]
fn nat4_lookup_cost() {
    assert_layouts();

    let builder = BenchNat4LookupSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open bench_nat4_lookup");
    let mut skel = open.load().expect("load bench_nat4_lookup");

    let packet = simple_ipv4_tcp(SRC, DST);

    /* ── HASH-side prefill ─────────────────────────────────────────── */

    // Static map: 16 distractors so the per-packet exact/wildcard misses
    // walk populated buckets like production.
    for i in 0..16u32 {
        let key = ser_key8(1, SEEDED_PORT + i as u16, i);
        skel.maps
            .bench_static_map
            .update(&key, &[0x0a, 0, 0, 0x02, 0, 0, 0, 0], MapFlags::ANY)
            .expect("fill bench_static_map distractor");
    }

    // Egress dyn: hit entry + 15 distractors.
    skel.maps
        .bench_egress_map
        .update(
            &ser_key8(1, SPORT_REG, SADDR),
            &ser_egress_value(NAT_IP, NAT_PORT, 1),
            MapFlags::ANY,
        )
        .expect("fill egress hit");
    for i in 0..15u32 {
        let key = ser_key8(1, 20000 + i as u16, SADDR.wrapping_add(i + 1));
        skel.maps
            .bench_egress_map
            .update(&key, &ser_egress_value(NAT_IP, 30000 + i as u16, 1), MapFlags::ANY)
            .expect("fill egress distractor");
    }

    // Ingress dyn: cross-check hit (egress view) + ingress-bench hit + distractors.
    skel.maps
        .bench_ingress_map
        .update(&ser_key8(0, NAT_PORT, NAT_IP), &ser_ingress_value(SADDR, SPORT_REG), MapFlags::ANY)
        .expect("fill ingress cross-check hit");
    skel.maps
        .bench_ingress_map
        .update(
            &ser_key8(0, DPORT_REG, DADDR),
            &ser_ingress_value(NAT_IP, INGRESS_VPORT),
            MapFlags::ANY,
        )
        .expect("fill ingress hit");
    for i in 0..14u32 {
        let key = ser_key8(0, 20000 + i as u16, NAT_IP.wrapping_add(i + 1));
        skel.maps
            .bench_ingress_map
            .update(&key, &ser_ingress_value(NAT_IP, 30000 + i as u16), MapFlags::ANY)
            .expect("fill ingress distractor");
    }

    // Timer map (NO_PREALLOC): egress steady entry + ingress steady entry + distractors.
    skel.maps
        .bench_timer_map
        .update(
            &ser_timer_key(DADDR, NAT_IP, DPORT_REG, NAT_PORT),
            &ser_timer_value(TIMER_CPORT),
            MapFlags::ANY,
        )
        .expect("fill egress timer hit");
    skel.maps
        .bench_timer_map
        .update(
            &ser_timer_key(SADDR, DADDR, SPORT_REG, DPORT_REG),
            &ser_timer_value(TIMER_CPORT),
            MapFlags::ANY,
        )
        .expect("fill ingress timer hit");
    for i in 0..6u32 {
        let key = ser_timer_key(DADDR, NAT_IP, 100 + i as u16, NAT_PORT);
        skel.maps
            .bench_timer_map
            .update(&key, &ser_timer_value(0), MapFlags::ANY)
            .expect("fill timer distractor");
    }

    // Port queue: one seeded port; hash_create pops and pushes it back every
    // run, so it never drains. Value = {u16 port, u16 gen}: the u32 LE
    // encoding of 32768 has the port in its low two bytes.
    skel.maps
        .bench_port_queue
        .update(&[], &(SEEDED_PORT as u32).to_ne_bytes(), MapFlags::ANY)
        .expect("seed port queue");

    // Ingress-static wildcard entry for the static-lookup evaluation set.
    let mut sv = [0u8; 8];
    sv[0..4].copy_from_slice(&ST_LAN_ADDR.to_ne_bytes());
    sv[4..6].copy_from_slice(&ST_LAN_PORT.to_ne_bytes());
    skel.maps
        .bench_static_map
        .update(&ser_key8(0, DPORT_REG, 0), &sv, MapFlags::ANY)
        .expect("fill ingress static hit");

    /* ── arena-side prefill (typed mmap access) ────────────────────── */

    let h = flow_hash(SADDR, DADDR, SPORT_REG, DPORT_REG);
    let h2 = flow_hash(DADDR, SADDR, DPORT_REG, SPORT_REG);

    {
        let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
        let t = &mut data.bench_tbl;
        // Session freelist 1..511 (slot 0 is the steady-state session).
        for i in 1..511usize {
            t.session_next[i] = (i + 1) as u32;
        }
        t.session_next[511] = u32::MAX;
        t.session_free_head = 1;
        // Endpoint freelist 1..127 (slot 0 is the steady-state endpoint).
        for i in 1..127usize {
            t.endpoint_next[i] = (i + 1) as u32;
        }
        t.endpoint_next[127] = u32::MAX;
        t.endpoint_free_head = 1;
        // Port bitmap: all free, cursor 0.
        t.bitmap = [0; 2];
        t.bitmap_cursor = 0;

        // Steady-state session 0 + both idx slots.
        t.idx_egress[(h as usize) & IDX_MASK] =
            types::bench_idx_slot { tag: h >> 48, sid: 0, r#gen: 1 };
        t.idx_ingress[(h2 as usize) & IDX_MASK] =
            types::bench_idx_slot { tag: h2 >> 48, sid: 0, r#gen: 1 };
        let s = &mut t.pool[0];
        *s = types::bench_session::default();
        s.state_word = 1; // ACTIVE-ish, nonzero → no advance-CAS branch taken
        s.r#gen = 1;
        s.nat_port = NAT_PORT;
        s.client_port = SPORT_REG;
        s.l4proto = IPPROTO_TCP;
        s.flags = 0; // non-ancestor → endpoint policy line read
        s.ep_idx = 0;
        t.eps[0] = types::bench_endpoint::default();
        t.eps[0].allow_reuse = 1;
        t.eps[0].r#gen = 1;

        // Static-lookup evaluation set. Sorted range table: 8192 single-port
        // entries at 1024 + 7*i; the hit entry (port = DPORT_REG) overwrites
        // slot k in place, staying sorted (p_k ≤ DPORT_REG < p_{k+1}).
        let st_k = ((DPORT_REG as u32 - 1024) / ST_PORT_STEP) as usize;
        for i in 0..ST_TABLE_N {
            let p = (1024 + i as u32 * ST_PORT_STEP) as u16;
            t.st_table[i] = types::bench_st_entry {
                port_lo: p,
                port_hi: p,
                protos: 1,
                _pad: 0,
                lan_addr: 0,
                lan_port: 0,
                _pad2: 0,
            };
        }
        t.st_table[st_k] = types::bench_st_entry {
            port_lo: DPORT_REG,
            port_hi: DPORT_REG,
            protos: 1,
            _pad: 0,
            lan_addr: ST_LAN_ADDR,
            lan_port: ST_LAN_PORT,
            _pad2: 0,
        };
        debug_assert!(st_k > 0 && st_k + 1 < ST_TABLE_N, "hit entry must have neighbours");
        debug_assert!(
            t.st_table[st_k - 1].port_hi < DPORT_REG && DPORT_REG < t.st_table[st_k + 1].port_lo,
            "table must stay sorted with the hit entry in place"
        );
        let sh = mix64(((DPORT_REG as u64) << 32) | IPPROTO_TCP as u64);
        t.st_idx[(sh as usize) & ST_IDX_MASK] =
            types::bench_st_idx_slot { tag: sh >> 48, ent: st_k as u32, _pad: 0 };
        // {valid:1 | protos:8 | lan_port:16 | lan_addr:32}
        t.st_direct[DPORT_REG as usize] =
            (1u64 << 63) | (1u64 << 48) | ((ST_LAN_PORT as u64) << 32) | ST_LAN_ADDR as u64;
    }

    /* ── measure (sequential: create's teardown frees the steady slots) ── */

    let sink = &skel.maps.bench_sink;

    let base = {
        let p = &skel.progs.bench_baseline;
        warmup_checked(p, &packet, BASELINE_PER_RUN, sink);
        timing(p, &packet)
    };

    let hash_egress = {
        let p = &skel.progs.bench_hash_egress;
        warmup_checked(p, &packet, HASH_EGRESS_PER_RUN, sink);
        timing(p, &packet)
    };

    let hash_ingress = {
        let p = &skel.progs.bench_hash_ingress;
        warmup_checked(p, &packet, HASH_INGRESS_PER_RUN, sink);
        timing(p, &packet)
    };

    let arena_egress = {
        let p = &skel.progs.bench_arena_egress;
        warmup_checked(p, &packet, ARENA_EGRESS_PER_RUN, sink);
        timing(p, &packet)
    };

    let arena_ingress = {
        let p = &skel.progs.bench_arena_ingress;
        warmup_checked(p, &packet, ARENA_INGRESS_PER_RUN, sink);
        timing(p, &packet)
    };

    let static_hash = {
        let p = &skel.progs.bench_static_hash;
        warmup_checked(p, &packet, STATIC_PER_RUN, sink);
        timing(p, &packet)
    };
    let static_binsearch = {
        let p = &skel.progs.bench_static_binsearch;
        warmup_checked(p, &packet, STATIC_PER_RUN, sink);
        timing(p, &packet)
    };
    let static_idx = {
        let p = &skel.progs.bench_static_idx;
        warmup_checked(p, &packet, STATIC_PER_RUN, sink);
        timing(p, &packet)
    };
    let static_direct = {
        let p = &skel.progs.bench_static_direct;
        warmup_checked(p, &packet, STATIC_PER_RUN, sink);
        timing(p, &packet)
    };

    // Free the two steady-state idx slots so bench_arena_create can claim
    // them fresh on every run.
    {
        let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
        data.bench_tbl.idx_egress[(h as usize) & IDX_MASK].tag = 0;
        data.bench_tbl.idx_ingress[(h2 as usize) & IDX_MASK].tag = 0;
    }

    let hash_create = {
        // Drop the steady-state egress entry: its key is the SAME flow the
        // create bench maps (packet-derived), and NOEXIST insert vs a
        // pre-existing entry would fail on every run.
        skel.maps
            .bench_egress_map
            .delete(&ser_key8(1, SPORT_REG, SADDR))
            .expect("drop steady egress hit entry");
        let p = &skel.progs.bench_hash_create;
        warmup_checked(p, &packet, HASH_CREATE_PER_RUN, sink);
        timing(p, &packet)
    };

    let arena_create = {
        let p = &skel.progs.bench_arena_create;
        zero_sink(sink);
        for _ in 0..WARMUP_BATCHES {
            sample_batch(p, &packet);
        }
        let runs = WARMUP_BATCHES as u64 * REPEAT as u64;
        let sink_val = read_sink(sink);
        assert!(
            sink_val >= runs * ARENA_CREATE_MIN && sink_val <= runs * ARENA_CREATE_MAX,
            "bench_arena_create sink {sink_val} outside the all-success range"
        );
        timing(p, &packet)
    };

    println!("--- NAT4 per-run cost (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("hash_egress", hash_egress, base);
    report("arena_egress", arena_egress, base);
    report("hash_ingress", hash_ingress, base);
    report("arena_ingress", arena_ingress, base);
    report("hash_create", hash_create, base);
    report("arena_create", arena_create, base);
    println!("--- static NAT lookup primitives (ingress shape: (proto, wan_port)) ---");
    report("hash(1x)", static_hash, base);
    report("binsearch", static_binsearch, base);
    report("st_idx", static_idx, base);
    report("direct", static_direct, base);
}
