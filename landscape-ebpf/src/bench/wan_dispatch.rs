//! Compare the steady-state hit cost of the IPv6 WAN dispatch lookup designs
//! discussed for `xdp_wan_intro`:
//!
//! - `bench_hash` 1x LRU hash lookup by the packet's /64
//!   (current dispatch-map path / cache step 1)
//! - `bench_lpm` 1x LPM trie lookup by a /64 trie key
//!   (the trie-only design)
//! - `bench_array_scan` linear scan of a double-buffered table carried by a
//!   single-slot ARRAY map (one helper call per packet, direct entry loads)
//! - `bench_arena_scan` the same scan over an arena (`__arena` global):
//!   every access is a plain load, zero helper calls
//! - `bench_arena_trie` a stride-8 (256-way) multibit trie carried by the
//!   arena, the arena twin of the kernel's `lpm_trie`: at most 8 dependent
//!   table loads per lookup, no helper call / matchlen recompute / RCU.
//!   Compared head-to-head with `bench_lpm` on the identical fill.
//! - `bench_baseline` same loop without any lookup; its cost is subtracted so
//!   the shared loop/packet-parse machinery cancels out.
//!
//! `BPF_PROG_TEST_RUN` syscall overhead (~us) dwarfs a single lookup (~ns), so
//! each program loops `BENCH_ITERS` times in one invocation and we report
//! `(variant - baseline) / BENCH_ITERS` per lookup.
//!
//! Run with: `cargo test -p landscape-ebpf --lib bench:: -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use super::bench_wan_dispatch::BenchWanDispatchSkelBuilder;
use super::bench_wan_dispatch::types::{
    addr_space_1, bench_scan_entry, bench_scan_tbl, wan_trie_half, wan_trie_node,
};
use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, v4_entry, wan_trie_publish as publish_prefix_entries,
};
use crate::maps::wan_trie::types::WanTrieTbl;
use crate::tests::route::packet_builder::{
    simple_ipv4_tcp, simple_ipv6_tcp_syn, simple_pppoe_ipv4,
};

const XDP_PASS: u32 = 2; // enum xdp_action: ABORTED=0, DROP=1, PASS=2

const WARMUP: usize = 5;
const REPS: usize = 50;
const BENCH_ITERS: u64 = 256;

const DST: [u8; 16] =
    [0xfd, 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x12, 0, 0, 0, 0, 0, 0, 0x00, 0x34];
const SRC: [u8; 16] =
    [0xfd, 0x00, 0xbb, 0xbb, 0xcc, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x01];

/// Trie-section destination: inside fd22:2222:33ab:1200::/56 (the nested hit),
/// which is itself inside fd22:2222:33::/40, clearly outside fd44:5555:33::/40.
const DST_TRIE: [u8; 16] =
    [0xfd, 0x22, 0x22, 0x22, 0x33, 0xab, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0x00, 0x56];

/// (prefix bytes, prefix length, value). DST is covered by the /56 entry.
const SMALL_TRIE: [([u8; 8], u32, u32); 3] = [
    ([0xfd, 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00], 56, 1), // hit
    ([0xfd, 0x00, 0xbb, 0xbb, 0xcc, 0x00, 0x00, 0x00], 60, 2),
    ([0xfd, 0x00, 0xdd, 0xdd, 0x00, 0xee, 0x00, 0xff], 64, 3),
];

/// 16 entries: ancestor /48, the small three, and 12 /64 siblings sharing the
/// hit prefix's /56 so the walk passes through a deeper branch point.
fn large_trie() -> Vec<([u8; 8], u32, u32)> {
    let mut entries = vec![([0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 48u32, 4u32)];
    entries.extend_from_slice(&SMALL_TRIE);
    for i in 0x20u8..=0x2b {
        let prefix = [0xfd, 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x00, i];
        entries.push((prefix, 64, 5));
    }
    entries
}

/// `n` entries (16 < n <= 64): ancestor /48, the /56 hit, and `n - 2` /64
/// distractors spread over byte6/byte7 so the trie branches at several depths.
fn spread_trie(n: usize) -> Vec<([u8; 8], u32, u32)> {
    let mut entries = vec![([0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 48u32, 4u32)];
    entries.push(([0xfd, 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00], 56, 1));
    for i in 0..(n - 2) {
        let mut prefix = [0xfd, 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00];
        prefix[6] = (i / 16) as u8;
        prefix[7] = 0x20 + (i % 16) as u8;
        entries.push((prefix, 64, 5));
    }
    entries
}

fn trie_key(prefix: &[u8; 8], plen: u32) -> [u8; 12] {
    let mut key = [0u8; 12];
    key[0..4].copy_from_slice(&plen.to_ne_bytes());
    key[4..12].copy_from_slice(prefix);
    key
}

fn fill_lpm(map: &impl MapCore, entries: &[([u8; 8], u32, u32)]) {
    for (prefix, plen, value) in entries {
        map.update(&trie_key(prefix, *plen), &value.to_ne_bytes(), MapFlags::ANY)
            .expect("fill bench_lpm entry");
    }
}

fn clear_lpm(map: &impl MapCore, entries: &[([u8; 8], u32, u32)]) {
    for (prefix, plen, _) in entries {
        let _ = map.delete(&trie_key(prefix, *plen));
    }
}

fn read_sink(map: &impl MapCore) -> u64 {
    let raw = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        .expect("read bench_sink")
        .expect("bench_sink entry missing");
    u64::from_ne_bytes(raw.as_slice().try_into().unwrap())
}

const SCAN_SLOTS: usize = 32;
const HIT_ROOT: u32 = 7;
const MISS_ROOT: u32 = 9;

/// Build one table half with `n - 1` /64 distractors that differ from DST in
/// the last byte, then the /56 hit entry in slot `n - 1` (worst-case scan).
fn scan_half(dst64: [u8; 8], n: usize) -> [bench_scan_entry; SCAN_SLOTS] {
    // The BPF side memcpys the packet bytes into a u64 register, i.e. the
    // host-endian interpretation of the packet bytes; masks/prefixes here must
    // be computed against that same value. A /56 still clears the low byte.
    let dst = u64::from_ne_bytes(dst64);
    let mut half = [bench_scan_entry::default(); SCAN_SLOTS];
    for (i, e) in half.iter_mut().enumerate().take(n) {
        if i == n - 1 {
            // /56 hit: the mask clears the last byte, so the cleared prefix matches
            e.mask = 0xffff_ffff_ffff_ff00;
            e.prefix_masked = dst & e.mask;
            e.root = HIT_ROOT;
        } else {
            // /64 distractor: full mask, last byte differs from the packet's
            e.mask = u64::MAX;
            e.prefix_masked = (dst & 0xffff_ffff_ffff_ff00) | (0x20 + i as u64);
            e.root = MISS_ROOT;
        }
        e.used = 1;
    }
    half
}

/// Serialize a table for the ARRAY variant (value = whole struct).
fn tbl_bytes(t: &bench_scan_tbl) -> Vec<u8> {
    let len = std::mem::size_of::<bench_scan_tbl>();
    let mut bytes = vec![0u8; len];
    let src = t as *const bench_scan_tbl as *const u8;
    unsafe { std::ptr::copy_nonoverlapping(src, bytes.as_mut_ptr(), len) };
    bytes
}

/// ARRAY variant publish: fill the spare half and flip `cur` in one whole-table
/// update. Returns the new `cur`.
fn array_publish(map: &impl MapCore, cur: u32, half: [bench_scan_entry; SCAN_SLOTS]) -> u32 {
    let spare = cur ^ 1;
    let mut tbl = bench_scan_tbl {
        cur: 0,
        pad: 0,
        tbl: [[bench_scan_entry::default(); SCAN_SLOTS]; 2],
    };
    tbl.tbl[spare as usize] = half;
    tbl.cur = spare;
    map.update(&0u32.to_ne_bytes(), &tbl_bytes(&tbl), MapFlags::ANY)
        .expect("publish scan table via ARRAY");
    spare
}

/// Arena variant publish: fill the spare half through the mmap'd `__arena`
/// globals, flip `cur` last (aligned u32 store is atomic on x86).
fn arena_publish(data: &mut addr_space_1, half: [bench_scan_entry; SCAN_SLOTS]) {
    let t = &mut data.bench_arena_tbl;
    let spare = t.cur ^ 1;
    t.tbl[spare as usize] = half;
    t.cur = spare;
}

const TRIE_POOL_NODES: usize = 2048; /* 2 * 32 * 32, three-level chunked */

/// Chunked node-pool indexing, mirroring the BPF side's flat `pool + idx`.
fn trie_node_at(h: &mut wan_trie_half, idx: usize) -> &mut wan_trie_node {
    &mut h.nodes[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

/// Chunked parallel `vals` array indexing.
fn trie_val_at(h: &mut wan_trie_half, idx: usize) -> &mut u32 {
    &mut h.vals[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

/// Entry set shared by the kernel lpm and the arena trie comparisons: the /56
/// hit nested under fd22:2222:33::/40, both /40 "ISP" prefixes (the fd22/fd44
/// example), and `n - 3` unique /32 distractors under fd00:xxYY::. All
/// prefixes are byte-aligned, exactly what the stride-8 trie encodes.
fn trie_entries(n: usize) -> Vec<([u8; 8], u32, u32)> {
    assert!(n >= 3);
    let mut entries = vec![
        ([0xfd, 0x22, 0x22, 0x22, 0x33, 0xab, 0x12, 0x00], 56, HIT_ROOT),
        ([0xfd, 0x22, 0x22, 0x22, 0x33, 0x00, 0x00, 0x00], 40, 4),
        ([0xfd, 0x44, 0x55, 0x55, 0x33, 0x00, 0x00, 0x00], 40, 5),
    ];
    for i in 0..(n - 3) {
        let mut prefix = [0u8; 8];
        prefix[0] = 0xfd;
        prefix[1] = 0x00;
        prefix[2] = 0x10 + (i >> 8) as u8;
        prefix[3] = (i & 0xff) as u8;
        entries.push((prefix, 32, MISS_ROOT));
    }
    entries
}

/// Build the trie into the spare half (control plane): structure first, then
/// mark each node's own prefix, then propagate values down in index order
/// (allocation guarantees parent idx < child idx). After propagation
/// `vals[idx]` is already the LPM answer for any dst reaching node idx.
/// Finally flip `cur`.
fn arena_trie_publish(data: &mut addr_space_1, entries: &[([u8; 8], u32, u32)]) {
    let t = &mut data.bench_trie_tbl;
    let spare = (t.cur ^ 1) as usize;
    let h = &mut t.halves[spare];
    // Zero the spare half (2MB memset beats a 2048-node Default construction).
    unsafe {
        std::ptr::write_bytes(
            h as *mut wan_trie_half as *mut u8,
            0,
            std::mem::size_of::<wan_trie_half>(),
        );
    }

    // Pass 1: structure + own-prefix marks (child = index + 1, vals = root).
    let mut cnt: usize = 1; // node 0 = root
    for (prefix, plen_bits, root) in entries {
        let depth = (*plen_bits / 8) as usize;
        let mut idx = 0usize;
        for &b in prefix.iter().take(depth) {
            let b = b as usize;
            let next = trie_node_at(h, idx).child[b >> 5][b & 31] as usize;
            idx = if next == 0 {
                let new = cnt;
                cnt += 1;
                assert!(cnt <= TRIE_POOL_NODES, "trie node pool exhausted");
                trie_node_at(h, idx).child[b >> 5][b & 31] = (new + 1) as u32;
                new
            } else {
                next - 1
            };
        }
        let val = trie_val_at(h, idx);
        assert_eq!(*val, 0, "conflicting prefixes at one trie node");
        *val = *root;
    }

    // Pass 2: inherit values down. Parent indices are always smaller than
    // child indices, so a single ascending sweep is a valid topological order.
    for idx in 0..cnt {
        let inherited = *trie_val_at(h, idx);
        if inherited == 0 {
            continue;
        }
        // Copy child slots out first: the node borrow must not overlap the
        // mutable vals borrows below.
        let children: Vec<u32> =
            trie_node_at(h, idx).child.iter().flatten().copied().filter(|c| *c != 0).collect();
        for c in children {
            let child_val = trie_val_at(h, (c - 1) as usize);
            if *child_val == 0 {
                *child_val = inherited;
            }
        }
    }

    h.node_cnt = cnt as u32;
    t.cur = spare as u32;
}

/// Publish namespace-tagged entries through the shared builder, casting the
/// generated arena global to the mirror type (layouts are pinned by the
/// wan_trie types tests).
fn publish_entries(data: &mut addr_space_1, entries: &[PrefixEntry]) {
    let tbl = unsafe { &mut *(&mut data.bench_trie_tbl as *mut _ as *mut WanTrieTbl) };
    publish_prefix_entries(tbl, entries).expect("wan_trie publish");
}

/// (N, kernel lpm sample, arena trie sample)
type TrieRow = (usize, (u128, u128), (u128, u128));

fn report_trie(rows: &[TrieRow], base2: (u128, u128)) {
    println!("--- trie section (dst under nested /56, walk depth 7) ---");
    for (n, lpm_n, trie_n) in rows {
        report(&format!("klpm({n})"), *lpm_n, base2);
        report(&format!("atrie({n})"), *trie_n, base2);
    }
}

/// Returns (min, median) of the kernel-reported program duration in ns.
fn measure(prog: &ProgramMut<'_>, packet: &[u8]) -> (u128, u128) {
    for _ in 0..WARMUP {
        let out = prog
            .test_run(ProgramInput { data_in: Some(packet), ..Default::default() })
            .expect("warmup test_run");
        assert_eq!(out.return_value, XDP_PASS, "prog did not return XDP_PASS");
    }
    let mut samples: Vec<u128> = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let out = prog
            .test_run(ProgramInput { data_in: Some(packet), ..Default::default() })
            .expect("test_run");
        assert_eq!(out.return_value, XDP_PASS, "prog did not return XDP_PASS");
        samples.push(out.duration.as_nanos());
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn report(name: &str, (min, med): (u128, u128), (base_min, base_med): (u128, u128)) {
    let per_min = min.saturating_sub(base_min) as f64 / BENCH_ITERS as f64;
    let per_med = med.saturating_sub(base_med) as f64 / BENCH_ITERS as f64;
    println!(
        "{name:<10} total(min/med) {min:>8}/{med:>8} ns   per-lookup(min/med) {per_min:>6.2}/{per_med:>6.2} ns"
    );
}

#[test]
#[ignore = "bench"]
fn wan_dispatch_lookup_cost() {
    let builder = BenchWanDispatchSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open bench_wan_dispatch");
    let mut skel = open.load().expect("load bench_wan_dispatch");

    let packet = simple_ipv6_tcp_syn(Ipv6Addr::from(SRC), Ipv6Addr::from(DST));

    // LRU hash prefill: the packet's /64 (hit) plus 15 distractors.
    let dst64: [u8; 8] = DST[0..8].try_into().unwrap();
    let mut hash_keys = vec![dst64];
    for i in 0x20u8..=0x2e {
        let mut key = dst64;
        key[7] = i;
        hash_keys.push(key);
    }
    for (i, key) in hash_keys.iter().enumerate() {
        skel.maps
            .bench_hash_map
            .update(key, &(100 + i as u32).to_ne_bytes(), MapFlags::ANY)
            .expect("fill bench_hash entry");
    }

    let base = measure(&skel.progs.bench_baseline, &packet);
    let hash = measure(&skel.progs.bench_hash, &packet);
    assert_eq!(read_sink(&skel.maps.bench_sink), BENCH_ITERS * 100, "bench_hash did not hit");

    fill_lpm(&skel.maps.bench_lpm_map, &SMALL_TRIE);
    let lpm_small = measure(&skel.progs.bench_lpm, &packet);
    assert_eq!(read_sink(&skel.maps.bench_sink), BENCH_ITERS, "bench_lpm(small) did not hit");

    clear_lpm(&skel.maps.bench_lpm_map, &SMALL_TRIE);
    let large = large_trie();
    fill_lpm(&skel.maps.bench_lpm_map, &large);
    let lpm_large = measure(&skel.progs.bench_lpm, &packet);
    assert_eq!(read_sink(&skel.maps.bench_sink), BENCH_ITERS, "bench_lpm(large) did not hit");
    clear_lpm(&skel.maps.bench_lpm_map, &large);

    // ARRAY-carried scan table: hit at the last slot of N.
    let mut _acur = array_publish(&skel.maps.bench_scan_tbl_map, 0, scan_half(dst64, 3));
    let array3 = measure(&skel.progs.bench_array_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "array_scan(3) did not hit"
    );

    _acur = array_publish(&skel.maps.bench_scan_tbl_map, _acur, scan_half(dst64, 16));
    let array16 = measure(&skel.progs.bench_array_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "array_scan(16) did not hit"
    );

    // Larger scans + matching trie sizes to locate the linear/trie crossover.
    let t32 = spread_trie(32);
    fill_lpm(&skel.maps.bench_lpm_map, &t32);
    let lpm32 = measure(&skel.progs.bench_lpm, &packet);
    assert_eq!(read_sink(&skel.maps.bench_sink), BENCH_ITERS, "bench_lpm(32) did not hit");

    let t48 = spread_trie(48);
    clear_lpm(&skel.maps.bench_lpm_map, &t32);
    fill_lpm(&skel.maps.bench_lpm_map, &t48);
    let lpm48 = measure(&skel.progs.bench_lpm, &packet);
    assert_eq!(read_sink(&skel.maps.bench_sink), BENCH_ITERS, "bench_lpm(48) did not hit");
    clear_lpm(&skel.maps.bench_lpm_map, &t48);

    _acur = array_publish(&skel.maps.bench_scan_tbl_map, _acur, scan_half(dst64, 32));
    let array32 = measure(&skel.progs.bench_array_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "array_scan(32) did not hit"
    );

    // Arena-carried scan table: same halves, published through the mmap'd globals.
    {
        let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
        arena_publish(data, scan_half(dst64, 3));
    }
    let arena3 = measure(&skel.progs.bench_arena_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "arena_scan(3) did not hit"
    );

    {
        let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
        arena_publish(data, scan_half(dst64, 16));
    }
    let arena16 = measure(&skel.progs.bench_arena_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "arena_scan(16) did not hit"
    );

    {
        let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
        arena_publish(data, scan_half(dst64, 32));
    }
    let arena32 = measure(&skel.progs.bench_arena_scan, &packet);
    assert_eq!(
        read_sink(&skel.maps.bench_sink),
        BENCH_ITERS * HIT_ROOT as u64,
        "arena_scan(32) did not hit"
    );

    // --- Arena trie vs kernel lpm, identical fill, dedicated packet ---
    // dst lives inside the nested /56 hit (walk depth 7) regardless of N, so
    // the trie row measures pure tree-walk latency, N-independent by design.
    let packet2 = simple_ipv6_tcp_syn(Ipv6Addr::from(SRC), Ipv6Addr::from(DST_TRIE));
    let base2 = measure(&skel.progs.bench_baseline, &packet2);
    let mut trie_rows: Vec<TrieRow> = Vec::new();
    for n in [3usize, 16, 32, 64, 256, 1024] {
        let entries = trie_entries(n);

        fill_lpm(&skel.maps.bench_lpm_map, &entries);
        let lpm_n = measure(&skel.progs.bench_lpm, &packet2);
        assert_eq!(
            read_sink(&skel.maps.bench_sink),
            BENCH_ITERS * HIT_ROOT as u64,
            "kernel lpm({n}) did not hit"
        );
        clear_lpm(&skel.maps.bench_lpm_map, &entries);

        {
            let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
            arena_trie_publish(data, &entries);
        }
        let trie_n = measure(&skel.progs.bench_arena_trie, &packet2);
        assert_eq!(
            read_sink(&skel.maps.bench_sink),
            BENCH_ITERS * HIT_ROOT as u64,
            "arena trie({n}) did not hit"
        );

        trie_rows.push((n, lpm_n, trie_n));
    }

    // --- Tagged namespaces through the same trie (v4 /24 hit, ppp session) ---
    // The baseline is the v6 one (base2): loop machinery cancels, the v4/ppp
    // ethertype parse differs by a couple of cycles at most.
    {
        let packet3 = simple_ipv4_tcp(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let tag_entries = vec![
            v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, HIT_ROOT).unwrap(),
            v4_entry(Ipv4Addr::new(198, 51, 100, 0), 24, MISS_ROOT).unwrap(),
        ];
        {
            let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
            publish_entries(data, &tag_entries);
        }
        let v4_row = measure(&skel.progs.bench_trie_v4, &packet3);
        assert_eq!(
            read_sink(&skel.maps.bench_sink),
            BENCH_ITERS * HIT_ROOT as u64,
            "trie v4 tag did not hit"
        );

        let packet4 =
            simple_pppoe_ipv4(0x1234, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        // test_run without ctx uses the loopback rxq, so the prog reads
        // ingress_ifindex == 1; seed the (ifindex, session) key accordingly.
        let ppp_entries = vec![ppp_entry(1, 0x1234, HIT_ROOT)];
        {
            let data = skel.maps.bench_arena_data.as_mut().expect("arena mmap data");
            publish_entries(data, &ppp_entries);
        }
        let ppp_row = measure(&skel.progs.bench_trie_ppp, &packet4);
        assert_eq!(
            read_sink(&skel.maps.bench_sink),
            BENCH_ITERS * HIT_ROOT as u64,
            "trie ppp tag did not hit"
        );

        println!("--- tagged namespaces (v4 /24 = 4 hops, ppp (ifindex,session) = 7 hops) ---");
        report("ttrie v4(2)", v4_row, base2);
        report("ttrie ppp(1)", ppp_row, base2);
    }

    println!("baseline   total(min/med) {}/{} ns over {} iters", base.0, base.1, BENCH_ITERS);
    report("hash", hash, base);
    report("lpm(3)", lpm_small, base);
    report("lpm(16)", lpm_large, base);
    report("lpm(32)", lpm32, base);
    report("lpm(48)", lpm48, base);
    report("array(3)", array3, base);
    report("array(16)", array16, base);
    report("array(32)", array32, base);
    report("arena(3)", arena3, base);
    report("arena(16)", arena16, base);
    report("arena(32)", arena32, base);
    report_trie(&trie_rows, base2);
}
