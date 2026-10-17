//! Per-read cost of the TC-path packet reads, the skb twin of
//! `wan_dispatch`'s lookup comparison:
//!
//! - `bench_tc_direct4/6` production read path: `VALIDATE_READ_DATA`
//!   direct data/data_end pointer walk (`_validate_read` in landscape.h)
//!   fetching saddr/daddr
//! - `bench_tc_helper4/6` `bpf_skb_load_bytes` copying the exact same
//!   address bytes into stack scratch, one helper call per read
//! - `bench_tc_scan4_full` / `bench_tc_scan6_full` one complete
//!   `scan_ipv4_full` / `scan_ipv6_full` per run: L3 header, fragment
//!   classification, ext-header walk (v6) and the L4 header peek; driven
//!   twice each — with a plain TCP packet (shallow path) and with an ICMP
//!   error packet (deepest path: embedded inner IP header walk plus the
//!   outer-daddr/inner-saddr cross-check)
//! - `bench_tc_read4_info` the two-stage flow per run:
//!   `scan_ipv4_into_idx` then `skb_read_ipv4_info` materializing the
//!   flow pair — the production "packet -> flow pair" cost
//! - `bench_tc_read4_icmp` / `bench_tc_read6_icmp` the deepest production
//!   read: `scan_*_full` on an ICMP error packet (classifies the error,
//!   walks the inner header) followed by `skb_read_*_info` re-reading the
//!   outer addresses, the inner daddr and the embedded inner L4 ports
//! - `bench_tc_baseline` same prologue and sink work without any read;
//!   its cost is subtracted so shared machinery cancels out.
//!
//! # Methodology
//!
//! Each program performs its read once per invocation; the driver batches
//! `REPEAT = 256` runs per BPF_PROG_TEST_RUN syscall via
//! `ProgramInput::repeat`, and the kernel reports the average per-run
//! duration for the batch (`net/bpf/test_run.c` divides the batch total
//! by the run count). Kernel-side batching keeps the loop out of the BPF
//! program entirely — an in-program 256-iteration loop around
//! `scan_ipv6_full` alone exhausts the verifier's 1M-insn budget — while
//! still amortizing the ~us syscall overhead.
//!
//! Every batch carries per-run shared cost (the kernel's bh/net_ctx
//! bookkeeping around each run, the ethertype prologue, the sink fold);
//! `bench_tc_baseline` pays exactly the same machinery without the read,
//! and we report variant_avg - baseline_avg.
//!
//! Sampling is interleaved: one batch per program per round, so monotone
//! drift (DVFS ramp-up, cache warming) hits every program equally and
//! cross-program comparisons stay honest; each program reports the
//! min/median of its per-round batch averages. A first non-interleaved
//! pass proves correctness — `bench_sink` accumulates one deterministic
//! value per run, so it must equal `runs * per_run_value` — and doubles
//! as the global warmup.
//!
//! Reference numbers (median per-op, kernel 6.12, the dev box this was
//! written on — **indicative only**: absolute values drift with
//! machine/DVFS/kernel build; only the magnitudes and ratios are meant
//! to be compared):
//!
//! ```text
//! v4       direct +1ns   helper +21ns   scan +11ns   read +8ns
//! v4 icmp  scan +14ns    read +19ns
//! v6       direct +5ns   helper +23ns   scan +12ns
//! v6 icmp  scan +19ns    read +26ns
//! ```
//!
//! Run with: `cargo test -p landscape-ebpf --lib --features bpf-test bench::skb_read -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use super::bench_skb_read::BenchSkbReadSkelBuilder;
use crate::tests::pkt::{
    build_icmpv4_error_with_inner_tcp_min_quote_eth, build_icmpv6_error_with_inner_ipv6_eth,
};
use crate::tests::pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn};

const TC_ACT_OK: u32 = 0;

/// Kernel-side BPF_PROG_TEST_RUN batching: one syscall runs the program
/// this many times and reports the average per-run duration.
const REPEAT: u32 = 256;

/// Correctness/warmup pass: batches per program (then the sink must hold
/// exactly `WARMUP_BATCHES * REPEAT * per_run`).
const WARMUP_BATCHES: usize = 5;
/// Timing pass: rounds of one batch per program; with
/// `SAMPLES_PER_ROUND` batches each, every program ends up with
/// `ROUNDS * SAMPLES_PER_ROUND` samples spread across the whole pass.
const ROUNDS: usize = 10;
const SAMPLES_PER_ROUND: usize = 5;

/// Value one baseline run folds into the sink.
const BASELINE_PER_RUN: u64 = 1;

const V4_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V4_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const V6_SRC: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xbbbb, 0xcc00, 0, 0, 0, 0, 1);
const V6_DST: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaaaa, 0, 0x12, 0, 0, 0, 0x34);

/// Port sum of the bench packets' TCP header (etherparse builder uses
/// src 12345 / dst 443); the sum is order-independent.
const V4_PORT_SUM: u64 = 12345 + 443;

/// eth(14) + iphdr(20, ihl=5) => l4 at 34, protocol TCP; plus pkt_type =
/// PKT_TCP_DATA_V2 (etherparse's .tcp() leaves SYN clear) and
/// fragment_id (etherparse defaults the ipv4 id to 0); every other idx
/// field of a plain TCP packet stays 0.
const V4_SCAN_SUM: u64 = 34 + 6 + PKT_TCP_DATA_V2 + FRAG_ID_SUM;
/// eth(14) + ipv6hdr(40) => l4 at 54, nexthdr TCP, no extension headers;
/// plus pkt_type = PKT_TCP_DATA_V2.
const V6_SCAN_SUM: u64 = 54 + 6 + PKT_TCP_DATA_V2;
/// PKT_TCP_DATA_V2 from einat_types.h (functional tests pin etherparse's
/// .tcp() to a flag-less header).
const PKT_TCP_DATA_V2: u64 = 1;
/// fragment_id of the bench packets: etherparse defaults the ipv4 id to
/// 0 (folded anyway so the id load cannot be dead-code eliminated).
const FRAG_ID_SUM: u64 = 0;

// ── ICMP error packets (functional-test builders) ──
//
// v4: eth(14) + outer iphdr(20) + icmphdr(8) + inner iphdr(20) + 8-byte
// TCP quote. Outer daddr == inner saddr, so scan_ipv4_full's cross-check
// passes and the ICMP error branch walks the embedded header:
// l4_offset 34, l4_protocol 1 (ICMP), icmp_error_l3_offset 34+8=42,
// icmp_error_inner_l4_offset 42+20=62, icmp_error_l4_protocol 6 (TCP);
// pkt_type stays PKT_CONNLESS_V2, fragment fields stay 0.
const V4_ICMP_SCAN_SUM: u64 = 34 + 1 + 42 + 62 + 6;
//
// v6: eth(14) + outer ipv6hdr(40) + icmp6hdr(8) + inner ipv6hdr(40) +
// 8-byte UDP quote: l4_offset 54, l4_protocol 58 (ICMPv6),
// icmp_error_l3_offset 54+8=62, inner l4 at 62+40=102 with protocol 17.
const V6_ICMP_SCAN_SUM: u64 = 54 + 58 + 62 + 102 + 17;

/// skb_read_ipv4_info on the v4 ICMP error: dst_addr = outer daddr
/// (10.0.0.1), src_addr = inner daddr (10.0.0.2), ports swapped from the
/// inner TCP quote (inner sport 1234 -> dst_port, inner dport 4321 ->
/// src_port).
const ICMP4_OUTER_DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ICMP4_INNER_DST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// skb_read_ipv6_info on the v6 ICMP error: dst_addr = outer daddr
/// (= inner saddr 2001:db8::1:1), src_addr = inner daddr
/// (2001:db8::1:2), ports swapped from the inner UDP quote (1234/4321).
const ICMP6_OUTER_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1, 0x1);
const ICMP6_INNER_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1, 0x2);
const ICMP_PORT_SUM: u64 = 1234 + 4321;

/// Host-order value a 32-bit BPF load of the address' network-order bytes
/// yields (BPF and this test run on the same machine).
fn v4_as_u64(addr: Ipv4Addr) -> u64 {
    u32::from_ne_bytes(addr.octets()) as u64
}

/// Sum of the four 32-bit host-order loads of the address' 16 bytes.
fn v6_as_u64(addr: Ipv6Addr) -> u64 {
    addr.octets().chunks(4).map(|c| u32::from_ne_bytes(c.try_into().unwrap()) as u64).sum()
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
    assert_eq!(out.return_value, TC_ACT_OK, "prog did not return TC_ACT_OK");
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
        "sink proves not every run performed the read"
    );
}

/// Interleaved timing pass: `samples[r]` collects batch averages of
/// program `r`; min/median over all rounds, immune to monotone drift.
fn time_interleaved(progs: &[&ProgramMut<'_>], packets: &[&[u8]]) -> Vec<(u128, u128)> {
    let mut samples: Vec<Vec<u128>> =
        vec![Vec::with_capacity(ROUNDS * SAMPLES_PER_ROUND); progs.len()];
    for _ in 0..ROUNDS {
        for (i, prog) in progs.iter().enumerate() {
            for _ in 0..SAMPLES_PER_ROUND {
                samples[i].push(sample_batch(prog, packets[i]));
            }
        }
    }
    samples
        .iter()
        .map(|v| {
            let mut v = v.clone();
            v.sort_unstable();
            (*v.first().unwrap(), v[v.len() / 2])
        })
        .collect()
}

/// Samples are already per-run averages: per-op = variant - baseline.
fn report(name: &str, (min, med): (u128, u128), (base_min, base_med): (u128, u128)) {
    let per_min = min.saturating_sub(base_min);
    let per_med = med.saturating_sub(base_med);
    println!(
        "{name:<12} avg(min/med) {min:>6}/{med:>6} ns   per-op(min/med) {per_min:>4}/{per_med:>4} ns"
    );
}

#[test]
#[ignore = "bench"]
fn skb_read_cost() {
    let builder = BenchSkbReadSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open bench_skb_read");
    let skel = open.load().expect("load bench_skb_read");

    let pkt4 = simple_ipv4_tcp(V4_SRC, V4_DST);
    let pkt6 = simple_ipv6_tcp_syn(V6_SRC, V6_DST);
    let pkt4i = build_icmpv4_error_with_inner_tcp_min_quote_eth();
    let pkt6i = build_icmpv6_error_with_inner_ipv6_eth();

    let v4_addr_sum = v4_as_u64(V4_SRC) + v4_as_u64(V4_DST);
    let v6_addr_sum = v6_as_u64(V6_SRC) + v6_as_u64(V6_DST);
    let icmp4_pair_sum = v4_as_u64(ICMP4_INNER_DST) + v4_as_u64(ICMP4_OUTER_DST) + ICMP_PORT_SUM;
    let icmp6_pair_sum = v6_as_u64(ICMP6_INNER_DST) + v6_as_u64(ICMP6_OUTER_DST) + ICMP_PORT_SUM;

    // Pass 1: sink proof (every run read) + global warmup. The scan twins
    // driven with the ICMP error packets exercise their deepest branch;
    // the read*_icmp twins pair a full scan with skb_read_*_info.
    for (prog, pkt, per_run) in [
        (&skel.progs.bench_tc_baseline, &pkt4, BASELINE_PER_RUN),
        (&skel.progs.bench_tc_direct4, &pkt4, v4_addr_sum),
        (&skel.progs.bench_tc_helper4, &pkt4, v4_addr_sum),
        (&skel.progs.bench_tc_scan4_full, &pkt4, V4_SCAN_SUM),
        (&skel.progs.bench_tc_read4_info, &pkt4, v4_addr_sum + V4_PORT_SUM),
        (&skel.progs.bench_tc_scan4_full, &pkt4i, V4_ICMP_SCAN_SUM),
        (&skel.progs.bench_tc_read4_icmp, &pkt4i, icmp4_pair_sum),
        (&skel.progs.bench_tc_baseline, &pkt6, BASELINE_PER_RUN),
        (&skel.progs.bench_tc_direct6, &pkt6, v6_addr_sum),
        (&skel.progs.bench_tc_helper6, &pkt6, v6_addr_sum),
        (&skel.progs.bench_tc_scan6_full, &pkt6, V6_SCAN_SUM),
        (&skel.progs.bench_tc_scan6_full, &pkt6i, V6_ICMP_SCAN_SUM),
        (&skel.progs.bench_tc_read6_icmp, &pkt6i, icmp6_pair_sum),
    ] {
        warmup_checked(prog, pkt, per_run, &skel.maps.bench_sink);
    }

    // Pass 2: interleaved timing, all families in one rotation so they
    // share DVFS/cache epochs too.
    let progs = [
        &skel.progs.bench_tc_baseline,
        &skel.progs.bench_tc_direct4,
        &skel.progs.bench_tc_helper4,
        &skel.progs.bench_tc_scan4_full,
        &skel.progs.bench_tc_read4_info,
        &skel.progs.bench_tc_scan4_full,
        &skel.progs.bench_tc_read4_icmp,
        &skel.progs.bench_tc_baseline,
        &skel.progs.bench_tc_direct6,
        &skel.progs.bench_tc_helper6,
        &skel.progs.bench_tc_scan6_full,
        &skel.progs.bench_tc_scan6_full,
        &skel.progs.bench_tc_read6_icmp,
    ];
    let packets = [
        &pkt4[..],
        &pkt4[..],
        &pkt4[..],
        &pkt4[..],
        &pkt4[..],
        &pkt4i[..],
        &pkt4i[..],
        &pkt6[..],
        &pkt6[..],
        &pkt6[..],
        &pkt6[..],
        &pkt6i[..],
        &pkt6i[..],
    ];
    let stats = time_interleaved(&progs, &packets);

    let (
        base4,
        direct4,
        helper4,
        scan4,
        read4,
        scan4i,
        read4i,
        base6,
        direct6,
        helper6,
        scan6,
        scan6i,
        read6i,
    ) = (
        stats[0], stats[1], stats[2], stats[3], stats[4], stats[5], stats[6], stats[7], stats[8],
        stats[9], stats[10], stats[11], stats[12],
    );

    println!("--- v4 (eth + iphdr + tcphdr, 8 address bytes, {REPEAT} runs/batch) ---");
    println!("baseline4    avg(min/med) {}/{} ns", base4.0, base4.1);
    report("direct4", direct4, base4);
    report("helper4", helper4, base4);
    report("scan4", scan4, base4);
    report("read4", read4, base4);
    println!("--- v4 icmp error (outer+inner iphdr, inner tcp quote) ---");
    report("scan4i", scan4i, base4);
    report("read4i", read4i, base4);

    println!("--- v6 (eth + ipv6hdr + tcphdr, 32 address bytes, {REPEAT} runs/batch) ---");
    println!("baseline6    avg(min/med) {}/{} ns", base6.0, base6.1);
    report("direct6", direct6, base6);
    report("helper6", helper6, base6);
    report("scan6", scan6, base6);
    println!("--- v6 icmp error (outer+inner ipv6hdr, inner udp quote) ---");
    report("scan6i", scan6i, base6);
    report("read6i", read6i, base6);
}
