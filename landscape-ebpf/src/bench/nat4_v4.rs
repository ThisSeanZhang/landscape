//! NAT4 v4 steady-state cost with the new map/state machine.
//!
//! The BPF variants call the production packet state phase directly and do
//! not rewrite the packet, so kernel-side `repeat` batching is stable. The
//! sink proves every repeat took the intended path.

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use super::bench_nat4_v4::BenchNat4V4SkelBuilder;

const REPEAT: u32 = 256;
const WARMUP_BATCHES: usize = 5;
const TIMING_BATCHES: usize = 50;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(50, 18, 88, 205);
const LAN_PORT: u16 = 12345;
const REMOTE_PORT: u16 = 443;
const NAT_PORT: u16 = 40000;

const PROTO_TCP: u8 = 6;
const KIND_DYNAMIC: u8 = 1;
const CT_ACTIVE: u64 = 20;
const TCP_STATE_SYN: u64 = 1;
const STATE_SHIFT: u64 = 56;
const STATE_ACTIVE: u64 = 1;
const NAPT_FROM_WAN_TCP_BASE: u32 = 65536;

const MAC_SRC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const MAC_DST: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

fn be32(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

fn tcp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1234_5678, 4096)
        .ack(1);
    let payload = [0u8; 0];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
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
    assert_eq!(out.return_value as i32, 0, "bench program returned non-OK");
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
        "sink proves not every run took the expected path"
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
    println!("{name:<18} per-run(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

#[test]
#[ignore = "bench"]
fn nat4_v4_steady_state_cost() {
    let builder = BenchNat4V4SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).expect("open bench_nat4_v4");
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = 14;
        rodata.land_nat_external_addr = be32(WAN_IP);
    }
    let skel = open.load().expect("load bench_nat4_v4");

    let lan_key = super::bench_nat4_v4::types::napt_from_lan_key {
        internal_addr: be32(LAN_IP),
        internal_port: LAN_PORT.to_be(),
        proto: PROTO_TCP,
        pad: 0,
    };
    let lan_value = super::bench_nat4_v4::types::napt_from_lan_value {
        external_port: NAT_PORT.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse: 1,
        generation: 0,
        trigger_addr: be32(REMOTE_IP),
        trigger_port: REMOTE_PORT.to_be(),
        pad: 0,
    };
    skel.maps
        .napt_from_lan
        .update(as_bytes(&lan_key), as_bytes(&lan_value), MapFlags::ANY)
        .expect("seed napt_from_lan");

    let wan_index = NAPT_FROM_WAN_TCP_BASE + u32::from(NAT_PORT);
    let wan_key = wan_index.to_ne_bytes();
    let wan_value = super::bench_nat4_v4::types::napt_from_wan_value {
        internal_addr: be32(LAN_IP),
        internal_port: LAN_PORT.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse: 1,
        trigger_addr: be32(REMOTE_IP),
        trigger_port: REMOTE_PORT.to_be(),
        pad0: 0,
        generation: 0,
        pad1: 0,
        state_ref: (STATE_ACTIVE << STATE_SHIFT) | 1,
    };
    skel.maps
        .napt_from_wan
        .update(&wan_key, as_bytes(&wan_value), MapFlags::ANY)
        .expect("seed napt_from_wan");

    let ct_key = super::bench_nat4_v4::types::napt_ct_key {
        internal_addr: be32(LAN_IP),
        remote_addr: be32(REMOTE_IP),
        internal_port: LAN_PORT.to_be(),
        remote_port: REMOTE_PORT.to_be(),
        proto: PROTO_TCP,
        pad: [0; 3],
    };
    let ct_value = super::bench_nat4_v4::types::napt_ct_value {
        external_port: NAT_PORT.to_be(),
        is_static: 0,
        pad0: 0,
        from_wan_gen: 0,
        status: CT_ACTIVE,
        client_status: TCP_STATE_SYN,
        server_status: TCP_STATE_SYN,
        ..Default::default()
    };
    skel.maps
        .napt_ct
        .update(as_bytes(&ct_key), as_bytes(&ct_value), MapFlags::ANY)
        .expect("seed napt_ct");

    let lan_pkt = tcp_pkt(LAN_IP, REMOTE_IP, LAN_PORT, REMOTE_PORT);
    let wan_pkt = tcp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT);
    let lan_miss_pkt = tcp_pkt(LAN_IP, REMOTE_IP, LAN_PORT + 1, REMOTE_PORT);
    let wan_miss_pkt = tcp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT + 1);
    let sink = &skel.maps.bench_sink;

    let base = {
        let p = &skel.progs.bench_nat4_v4_baseline;
        warmup_checked(p, &lan_pkt, sink);
        timing(p, &lan_pkt)
    };

    let lan = {
        let p = &skel.progs.bench_nat4_v4_lan_steady;
        warmup_checked(p, &lan_pkt, sink);
        timing(p, &lan_pkt)
    };
    let wan = {
        let p = &skel.progs.bench_nat4_v4_wan_steady;
        warmup_checked(p, &wan_pkt, sink);
        timing(p, &wan_pkt)
    };
    let lan_miss = {
        let p = &skel.progs.bench_nat4_v4_lan_miss;
        warmup_checked(p, &lan_miss_pkt, sink);
        timing(p, &lan_miss_pkt)
    };
    let wan_miss = {
        let p = &skel.progs.bench_nat4_v4_wan_miss;
        warmup_checked(p, &wan_miss_pkt, sink);
        timing(p, &wan_miss_pkt)
    };

    println!("--- NAT4 v4 state phase (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("lan_steady", lan, base);
    report("wan_steady", wan, base);
    report("lan_miss", lan_miss, base);
    report("wan_miss", wan_miss, base);
}
