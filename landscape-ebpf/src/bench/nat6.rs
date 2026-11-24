//! Stateful NPTv6 (`xdp_nat6` / `nat6_resolve`) steady-state and miss cost.
//!
//! Aligned with [`super::nat4_v4`]:
//!
//! - `baseline`: `xdp_nat_read6` header scan + TCP port/phase extraction.
//! - `egress_steady`: `nat6_timer_map` session hit + TCP state check + atomic
//!   packet/byte accounting + `/60` NPTv6 WAN prefix blend + L4 checksum delta.
//! - `egress_state_only`: pure `nat6_resolve` state phase without prefix/csum
//!   folding, isolating CT lookup + state advance for direct comparison with
//!   `nat4_v4::lan_steady`.
//! - `ingress_steady`: `nat6_timer_map` session hit + TCP state check + atomic
//!   packet/byte accounting + LAN prefix restore + L4 checksum delta.
//! - `egress_miss` / `ingress_miss`: unseeded TCP ACK missing `nat6_timer_map`
//!   and walking both exact and wildcard `nat6_static_map` lookups before
//!   returning `NAT_OP_ERR`.
//!
//! Run with:
//! `cargo test -p landscape-ebpf --lib --features bpf-test bench::nat6:: -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::str::FromStr;

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use super::bench_nat6::BenchNat6SkelBuilder;
use crate::{
    maps::{
        Nat6MappingKey, Nat6TimerKey, Nat6TimerValue,
        nat::{StaticNatMappingV6Item, add_static_nat6_mapping},
    },
    stages::nat6::{compute_npt_mask, wan_ro_prefix6},
    tests::isolated_pin_root,
};

const XDP_PASS: u32 = 2;

const REPEAT: u32 = 256;
const WARMUP_BATCHES: usize = 5;
const TIMING_BATCHES: usize = 50;

const WAN_IFINDEX: u32 = 6;
const PREFIX_LEN: u8 = 60;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const TIMER_ACTIVE: u64 = 20;
const TCP_BOTH_SYN: u64 = 0b11;

const CLIENT_PORT: u16 = 12345;
const REMOTE_PORT: u16 = 443;

const MAC_SRC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const MAC_DST: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

/// Delegated WAN `/60` base (`2409:8888:6666:4f21::` -> `/60` keeps low nibble
/// `0x5` from LAN prefix `fd00:1234:5678:abc5::`, producing `2409:8888:6666:4f25`).
const EXPECTED_LAN_PREFIX: [u8; 8] = [0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0xab, 0xc5];
const EXPECTED_WAN_PREFIX: [u8; 8] = [0x24, 0x09, 0x88, 0x88, 0x66, 0x66, 0x4f, 0x25];

fn wan_prefix_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::100").unwrap()
}

fn wan_translated_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap()
}

fn remote_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
}

fn npt_id_mask(prefix_len: u8) -> u8 {
    if prefix_len >= 64 { 0 } else { ((1u16 << (64 - prefix_len)) - 1) as u8 }
}

fn tcp6_ack_pkt(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv6(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1234_5678, 65535)
        .ack(1);
    let payload = [0u8; 0];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build ipv6 tcp ack packet");
    pkt
}

fn timer_key_for(
    local_ip: Ipv6Addr,
    client_port: u16,
    prefix_len: u8,
    remote: Ipv6Addr,
    remote_port: u16,
) -> Nat6TimerKey {
    let bytes = local_ip.octets();
    let mut client_suffix = [0u8; 8];
    client_suffix.copy_from_slice(&bytes[8..]);

    Nat6TimerKey {
        local: Nat6MappingKey {
            client_suffix,
            client_port: client_port.to_be(),
            id_byte: bytes[7] & npt_id_mask(prefix_len),
            l4_protocol: PROTO_TCP,
        },
        remote_addr: remote.octets(),
        remote_port: remote_port.to_be(),
        _pad: 0,
    }
}

fn seed_active_ct6(timer_map: &impl MapCore, key: &Nat6TimerKey, lan_src: Ipv6Addr) {
    let mut value = Nat6TimerValue {
        tcp_flags: TCP_BOTH_SYN,
        status: TIMER_ACTIVE,
        is_trigger: 1,
        allow_reuse: 0,
        gress: 1,
        is_static: 0,
        need_prefix_replace: 1,
        ifindex: WAN_IFINDEX,
        ..Default::default()
    };
    value.client_prefix.copy_from_slice(&lan_src.octets()[..8]);

    timer_map
        .update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
        .expect("seed active nat6_timer_map entry");
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

fn sample_batch(prog: &ProgramMut<'_>, packet: &[u8]) -> u128 {
    let out = prog
        .test_run(ProgramInput {
            data_in: Some(packet),
            repeat: REPEAT,
            ..Default::default()
        })
        .expect("test_run");
    assert_eq!(out.return_value, XDP_PASS, "bench_nat6 program did not return XDP_PASS");
    out.duration.as_nanos()
}

fn warmup_checked(prog: &ProgramMut<'_>, packet: &[u8], sink: &impl MapCore) {
    zero_sink(sink);
    for _ in 0..WARMUP_BATCHES {
        sample_batch(prog, packet);
    }
    assert_eq!(
        read_sink(sink),
        WARMUP_BATCHES as u64 * REPEAT as u64,
        "sink proves not every run took the expected NPTv6 path"
    );
}

fn timing(prog: &ProgramMut<'_>, packet: &[u8]) -> (u128, u128) {
    let mut samples = Vec::with_capacity(TIMING_BATCHES);
    for _ in 0..TIMING_BATCHES {
        samples.push(sample_batch(prog, packet));
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn report(name: &str, (min, med): (u128, u128), base: (u128, u128)) {
    let per_min = min.saturating_sub(base.0) as f64;
    let per_med = med.saturating_sub(base.1) as f64;
    println!("{name:<20} per-run(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

#[test]
#[ignore = "bench"]
fn nat6_steady_state_cost() {
    let pin_root = isolated_pin_root("bench-nat6");
    let mut builder = BenchNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).expect("set pin_root_path");
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).expect("open bench_nat6");
    {
        let rodata = open.maps.rodata_data.as_deref_mut().expect("bench_nat6 rodata");
        rodata.current_ifindex = WAN_IFINDEX;
        rodata.current_l3_offset = 14;
        rodata.wan_ro_prefix6.b = wan_ro_prefix6(Some(wan_prefix_ip()));
        rodata.wan_ro_npt_mask = compute_npt_mask(PREFIX_LEN);
        rodata.expected_wan_prefix = u64::from_ne_bytes(EXPECTED_WAN_PREFIX);
        rodata.expected_lan_prefix = u64::from_ne_bytes(EXPECTED_LAN_PREFIX);
    }
    let skel = open.load().expect("load bench_nat6");

    let lan_src = lan_host_ip();
    let wan_dst = wan_translated_ip();
    let remote = remote_ip();

    // Seed active session + 31 distractors in `nat6_timer_map`.
    let hit_key = timer_key_for(lan_src, CLIENT_PORT, PREFIX_LEN, remote, REMOTE_PORT);
    seed_active_ct6(&skel.maps.nat6_timer_map, &hit_key, lan_src);
    for i in 0..31u16 {
        let distract_key =
            timer_key_for(lan_src, 20000 + i, PREFIX_LEN, remote, REMOTE_PORT.wrapping_add(i));
        seed_active_ct6(&skel.maps.nat6_timer_map, &distract_key, lan_src);
    }

    // Seed distractors in `nat6_static_map` so miss-path static lookups walk populated buckets.
    let static_distractors: Vec<StaticNatMappingV6Item> = (0..16u16)
        .map(|i| StaticNatMappingV6Item {
            port: 30000 + i,
            lan_ip: Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0xabc5, 0, 0, 0, 0x200 + i),
            l4_protocol: PROTO_UDP,
        })
        .collect();
    add_static_nat6_mapping(&skel.maps.nat6_static_map, static_distractors);

    let egress_pkt = tcp6_ack_pkt(lan_src, remote, CLIENT_PORT, REMOTE_PORT);
    let ingress_pkt = tcp6_ack_pkt(remote, wan_dst, REMOTE_PORT, CLIENT_PORT);
    let egress_miss_pkt = tcp6_ack_pkt(lan_src, remote, CLIENT_PORT + 1, REMOTE_PORT);
    let ingress_miss_pkt = tcp6_ack_pkt(remote, wan_dst, REMOTE_PORT, CLIENT_PORT + 1);
    let sink = &skel.maps.bench_sink;

    let base = {
        let p = &skel.progs.bench_nat6_baseline;
        warmup_checked(p, &egress_pkt, sink);
        timing(p, &egress_pkt)
    };
    let egress_steady = {
        let p = &skel.progs.bench_nat6_egress_steady;
        warmup_checked(p, &egress_pkt, sink);
        timing(p, &egress_pkt)
    };
    let egress_state_only = {
        let p = &skel.progs.bench_nat6_egress_state_only;
        warmup_checked(p, &egress_pkt, sink);
        timing(p, &egress_pkt)
    };
    let ingress_steady = {
        let p = &skel.progs.bench_nat6_ingress_steady;
        warmup_checked(p, &ingress_pkt, sink);
        timing(p, &ingress_pkt)
    };
    let egress_miss = {
        let p = &skel.progs.bench_nat6_egress_miss;
        warmup_checked(p, &egress_miss_pkt, sink);
        timing(p, &egress_miss_pkt)
    };
    let ingress_miss = {
        let p = &skel.progs.bench_nat6_ingress_miss;
        warmup_checked(p, &ingress_miss_pkt, sink);
        timing(p, &ingress_miss_pkt)
    };

    println!("--- NAT6 XDP reader baseline (kernel repeat={REPEAT}) ---");
    println!(
        "{:<20} per-run(min/med) {:>7.2}/{:>7.2} ns",
        "baseline", base.0 as f64, base.1 as f64
    );
    println!("--- NAT6 XDP stateful NPTv6 (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("egress_steady", egress_steady, base);
    report("egress_state_only", egress_state_only, base);
    report("ingress_steady", ingress_steady, base);
    report("egress_miss", egress_miss, base);
    report("ingress_miss", ingress_miss, base);
}
