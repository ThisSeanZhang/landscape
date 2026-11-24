//! Route data-plane per-packet cost across IPv4 and IPv6 LAN-to-WAN paths.
//!
//! Covers both stage-isolated (`Tier-1`) and tail-called end-to-end (`Tier-2`)
//! dimensions for fair pre-c3 vs post-c3 comparison:
//!
//! - `baseline_v4` / `baseline_v6`: production packet scan + L3 context read +
//!   broadcast guard (`scan_route_packet` + `route4/6_read_context_from_scan`).
//! - `lan_cache_hit_v4` / `lan_cache_hit_v6` (Tier-1): steady-state LAN cache
//!   hit via `route4/6_search_cache_in_lan` (including the realistic
//!   `WAN_CACHE` miss that precedes `LAN_CACHE`), measured for both L3/PPPoE
//!   targets (`has_mac = 0`) and Ethernet targets (`has_mac = 1`).
//! - `lan_cold_resolve_v4` / `lan_cold_resolve_v6` (Tier-1): uncached policy
//!   verdict + ECMP slot selection (`match_flow_id` MAC/IP LPM -> `flow_ip_map`
//!   LPM + `flow_dns_map` LRU hash priority arbitration -> `rt_slot_map`
//!   16-slot hash), measured at both `small (8)` and `large (1024)` prefix/DNS
//!   rule counts, and for both IP-prefix hits and higher-priority DNS overrides.
//! - `lan_cold_full_v4` / `lan_cold_full_v6` (Tier-1): full uncached
//!   LAN-ingress lookup chain (`route4/6_search_cache_in_lan` miss +
//!   `rt4/6_lan_map` LPM check miss + `flow_verdict` + `rt_slot_map` pick) at
//!   1024 entries.
//! - `lan_cache_hit_v4/6_e2e` & `lan_cold_resolve_v4/6_e2e` (Tier-2): single
//!   `BPF_PROG_TEST_RUN` tail-call chain (`lan_route -> bench_wan_egress_l2_v4/6`)
//!   replicating `tc_wan_egress_root`'s `prepare_forwarded_ipv4/6` L2 rewrite
//!   (`.rodata egress_binding` + `.bss confirmed_gateway_mac(6)`), preventing
//!   stage-shift illusion when comparing Ethernet WAN paths against pre-c3.
//!
//! Run with:
//! `cargo test -p landscape-ebpf --lib --features bpf-test bench::route:: -- --ignored --nocapture`

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};
use std::str::FromStr;

use landscape_common::{
    flow::{
        FlowMarkInfo,
        ip_mark::{IpConfig, IpMarkInfo},
        mark::{FlowMark, FlowMarkAction},
    },
    net::MacAddr,
    sys_service::route_service::{RouteTargetInfo, WanRouteTarget},
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use super::bench_route::{BenchRouteSkel, BenchRouteSkelBuilder, types::wan_egress_binding};
use crate::{
    LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE,
    maps::{
        Route4CacheValue, Route6CacheValue,
        flow::types::FlowMatchKey,
        flow_dns::{create_flow_dns_inner_map_v4, create_flow_dns_inner_map_v6},
        flow_wanip::{create_inner_flow_match_map_v4, create_inner_flow_match_map_v6},
        route::{replace_wan_route_slots_v4_with_map, replace_wan_route_slots_v6_with_map},
    },
    tests::{
        TestSkb,
        helper::map::{
            LAN_CACHE, LAN_ROUTE_TYPE, WAN_CACHE, as_bytes, create_route4_cache_inner_map,
            create_route6_cache_inner_map, insert_ip_mac_v4, insert_route4_lan_entry,
            insert_route6_lan_entry, lookup_inner_map, make_rt4_cache_key, make_rt6_cache_key,
            put_rt4_cache_value, put_rt6_cache_value, seed_flow_match_mac,
        },
        isolated_pin_root,
        pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
    },
};

const REPEAT: u32 = 256;
const WARMUP_BATCHES: usize = 5;
const TIMING_BATCHES: usize = 50;

const SMALL_RULES: usize = 8;
const LARGE_RULES: usize = 1024;

const LO_IFINDEX: u32 = 1; // loopback in PROG_TEST_RUN
const WAN1_IFINDEX: u32 = 11;
const WAN2_IFINDEX: u32 = 12;
const LAN_IFINDEX: u32 = 10;

const WAN1_LINK_CHAIN_ID: u16 = 2;
const WAN2_LINK_CHAIN_ID: u16 = 3;
const BENCH_EGRESS_SLOT_V4: u32 = 0;
const BENCH_EGRESS_SLOT_V6: u32 = 1;

/// Source flow matched via `flow_match_map` (subnet IP match overrides MAC match).
const MATCHED_SRC_FLOW_ID: u32 = 2;
const MAC_FALLBACK_FLOW_ID: u32 = 1;

/// Policy marks resolved by `route4/6_flow_verdict`:
/// - `MARK_CACHE_HIT` (0x0303): steady-state cached verdict (Flow 3)
/// - `MARK_IP_HIT`    (0x0304): LPM destination prefix hit (Flow 4, prio 200)
/// - `MARK_DNS_WIN`   (0x0305): DNS hash override (Flow 5, prio 50 <= 200)
/// - `MARK_DISTRACT`  (0x0302): ancestor/sibling distractor rules (Flow 2)
const MARK_CACHE_HIT: u32 = 0x0303;
const MARK_IP_HIT: u32 = 0x0304;
const MARK_DNS_WIN: u32 = 0x0305;
const MARK_DISTRACT: u32 = 0x0302;

/// `simple_ipv4_tcp` and `simple_ipv6_tcp_syn` emit source MAC `02:00:00:00:00:01`.
const PKT_SRC_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const ROUTER_SRC_MAC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01];
const GW_DST_MAC_STR: &str = "02:11:22:33:44:55";
const ROUTER_DEV_MAC_STR: &str = "02:aa:bb:cc:dd:ee";

const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 101, 10);
const HOT_PPPOE_DST_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const HOT_ETH_DST_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 11);
const COLD_IP_DST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 42);
const COLD_DNS_DST_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 84);
const WAN_LOCAL_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 10);
const WAN_MASK_V4: [u8; 4] = [255, 255, 255, 0];
const WAN_GW_V4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

fn client_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:101::10").unwrap()
}

fn hot_pppoe_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:113::10").unwrap()
}

fn hot_eth_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:113::11").unwrap()
}

fn cold_ip_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:abcd:1234::42").unwrap()
}

fn cold_dns_dst_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:abcd:1234::84").unwrap()
}

fn wan_local_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:ffff::10").unwrap()
}

fn wan_gw_v6() -> Ipv6Addr {
    Ipv6Addr::from_str("fe80::1").unwrap()
}

fn mac_to_u64(mac: [u8; 6]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[..6].copy_from_slice(&mac);
    u64::from_ne_bytes(bytes)
}

fn wire_prog(map: &impl MapCore, slot: u32, prog: &ProgramMut<'_>) {
    let fd = prog.as_fd().as_raw_fd();
    map.update(&slot.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
        .expect("wire bench_egress_chain prog");
}

#[allow(clippy::too_many_arguments)]
fn seed_rt4_cache_entry(
    outer_map: &impl MapCore,
    cache_index: u32,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
    link_chain_id: u16,
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt4_cache_key(local, remote);
    let value = Route4CacheValue {
        mark_value,
        ifindex,
        has_mac: u8::from(has_mac),
        is_docker: 0,
        link_chain_id,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v4 cache entry");
}

#[allow(clippy::too_many_arguments)]
fn seed_rt6_cache_entry(
    outer_map: &impl MapCore,
    cache_index: u32,
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ifindex: u32,
    has_mac: bool,
    mark_value: u32,
    link_chain_id: u16,
) {
    let inner = lookup_inner_map(outer_map, cache_index);
    let key = make_rt6_cache_key(local, remote);
    let value = Route6CacheValue {
        mark_value,
        ifindex,
        has_mac: u8::from(has_mac),
        is_docker: 0,
        link_chain_id,
        ..Default::default()
    };
    inner
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert route v6 cache entry");
}

fn flow_mark_from_raw(raw: u32) -> FlowMark {
    let flow_id = (raw & 0xff) as u8;
    FlowMark::new(FlowMarkAction::Redirect, flow_id, false)
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
    assert_eq!(out.return_value as i32, 0, "bench_route program returned non-OK");
    out.duration.as_nanos()
}

fn sample_batch_e2e(prog: &ProgramMut<'_>, packet: &[u8], verify_gw_mac: Option<[u8; 6]>) -> u128 {
    let mut ctx = TestSkb { ifindex: LO_IFINDEX, ..Default::default() };
    let mut out_buf = if verify_gw_mac.is_some() { vec![0u8; packet.len()] } else { Vec::new() };
    let (ret, duration_ns) = {
        let out = prog
            .test_run(ProgramInput {
                data_in: Some(packet),
                data_out: if verify_gw_mac.is_some() { Some(&mut out_buf) } else { None },
                context_in: Some(ctx.as_mut_bytes()),
                repeat: REPEAT,
                ..Default::default()
            })
            .expect("test_run e2e");
        (out.return_value as i32, out.duration.as_nanos())
    };
    assert_eq!(ret, 0, "bench_route e2e program returned non-OK");
    if let Some(expected_gw) = verify_gw_mac {
        assert_eq!(&out_buf[..6], &expected_gw, "Tier-2 E2E dst MAC mismatch");
        assert_eq!(&out_buf[6..12], &ROUTER_SRC_MAC, "Tier-2 E2E src MAC mismatch");
        assert_eq!(&out_buf[12..], &packet[12..], "Tier-2 E2E mutated bytes past L2 MACs");
    }
    duration_ns
}

fn measure_checked(
    prog: &ProgramMut<'_>,
    packet: &[u8],
    expected_per_run: u64,
    sink: &impl MapCore,
) -> (u128, u128) {
    zero_sink(sink);
    for _ in 0..WARMUP_BATCHES {
        sample_batch(prog, packet);
    }
    assert_eq!(
        read_sink(sink),
        (WARMUP_BATCHES as u64 * REPEAT as u64) * expected_per_run,
        "sink mismatch: not every run hit the expected route path/mark"
    );

    let mut samples = Vec::with_capacity(TIMING_BATCHES);
    for _ in 0..TIMING_BATCHES {
        samples.push(sample_batch(prog, packet));
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn measure_checked_e2e(
    prog: &ProgramMut<'_>,
    packet: &[u8],
    expected_per_run: u64,
    expected_gw_mac: [u8; 6],
    sink: &impl MapCore,
) -> (u128, u128) {
    zero_sink(sink);
    for _ in 0..WARMUP_BATCHES {
        sample_batch_e2e(prog, packet, Some(expected_gw_mac));
    }
    assert_eq!(
        read_sink(sink),
        (WARMUP_BATCHES as u64 * REPEAT as u64) * expected_per_run,
        "Tier-2 E2E sink mismatch: tail-call or wan_egress L2 verification failed"
    );

    let mut samples = Vec::with_capacity(TIMING_BATCHES);
    for _ in 0..TIMING_BATCHES {
        samples.push(sample_batch_e2e(prog, packet, None));
    }
    samples.sort_unstable();
    (*samples.first().unwrap(), samples[samples.len() / 2])
}

fn report(name: &str, (min, med): (u128, u128), base: (u128, u128)) {
    let per_min = min.saturating_sub(base.0) as f64;
    let per_med = med.saturating_sub(base.1) as f64;
    println!("{name:<28} per-pkt(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

fn report_e2e(name: &str, (min, med): (u128, u128), base: (u128, u128)) {
    let per_min = min.saturating_sub(base.0) as f64;
    let per_med = med.saturating_sub(base.1) as f64;
    println!("{name:<32} per-pkt(min/med) {per_min:>7.2}/{per_med:>7.2} ns");
}

#[allow(clippy::field_reassign_with_default)]
fn seed_flow_match_subnet_v4(map: &impl MapCore, net: Ipv4Addr, prefix_len: u8, flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 32 + u32::from(prefix_len);
    key.l3_protocol = LANDSCAPE_IPV4_TYPE;
    key.is_match_ip = 1;
    key.set_src_ipv4_be(net.to_bits());
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert v4 subnet flow_match entry");
}

#[allow(clippy::field_reassign_with_default)]
fn seed_flow_match_subnet_v6(map: &impl MapCore, net: Ipv6Addr, prefix_len: u8, flow_id: u32) {
    let mut key = FlowMatchKey::default();
    key.prefixlen = 32 + u32::from(prefix_len);
    key.l3_protocol = LANDSCAPE_IPV6_TYPE;
    key.is_match_ip = 1;
    key.set_src_ipv6(net);
    map.update(as_bytes(&key), as_bytes(&flow_id), MapFlags::ANY)
        .expect("insert v6 subnet flow_match entry");
}

/// Build `total` IPv4 destination LPM rules (`total >= 8`), nesting ancestor
/// prefixes (`/8` -> `/14` -> `/16` -> `/20` -> `/22` -> `/24` hit) and `/28`
/// child branches around `198.51.100.0/24` so the kernel LPM trie traverses
/// realistic internal branch nodes and backtracks to the `/24` match.
fn build_ip4_rules(total: usize) -> Vec<IpMarkInfo> {
    assert!(total >= SMALL_RULES);
    let distract = flow_mark_from_raw(MARK_DISTRACT);
    let hit = flow_mark_from_raw(MARK_IP_HIT);

    let mut rules = vec![
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 0, 0, 0)),
                prefix: 8,
            },
            priority: 500,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 48, 0, 0)),
                prefix: 14,
            },
            priority: 400,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 0, 0)),
                prefix: 16,
            },
            priority: 350,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 96, 0)),
                prefix: 20,
            },
            priority: 300,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 22,
            },
            priority: 250,
        },
        IpMarkInfo {
            mark: hit,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 24,
            },
            priority: 200,
        },
        // Deeper /28 children that do NOT cover .42 or .84 force deeper trie walk.
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                prefix: 28,
            },
            priority: 150,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 128)),
                prefix: 28,
            },
            priority: 150,
        },
    ];

    for i in 0..(total - SMALL_RULES) {
        let b1 = ((i >> 8) & 0xff) as u8;
        let b2 = (i & 0xff) as u8;
        rules.push(IpMarkInfo {
            mark: distract,
            cidr: IpConfig {
                ip: IpAddr::V4(Ipv4Addr::new(100, b1, b2, 0)),
                prefix: 24,
            },
            priority: 300,
        });
    }
    assert_eq!(rules.len(), total);
    rules
}

/// Build `total` IPv4 DNS rule entries (`total >= 1`): `COLD_DNS_DST_V4` wins
/// priority arbitration (`50 <= 200`), while `COLD_IP_DST_V4` misses.
fn build_dns4_rules(total: usize) -> Vec<FlowMarkInfo> {
    assert!(total >= 1);
    let mut rules = Vec::with_capacity(total);
    rules.push(FlowMarkInfo {
        ip: IpAddr::V4(COLD_DNS_DST_V4),
        mark: MARK_DNS_WIN,
        priority: 50,
    });
    for i in 1..total {
        let b1 = ((i >> 8) & 0xff) as u8;
        let b2 = (i & 0xff) as u8;
        rules.push(FlowMarkInfo {
            ip: IpAddr::V4(Ipv4Addr::new(198, 18, b1, b2)),
            mark: MARK_DISTRACT,
            priority: 100,
        });
    }
    rules
}

/// IPv6 twin of [`build_ip4_rules`]: nested prefixes `/32` -> `/40` -> `/48` ->
/// `/56` -> `/60` -> `/64` (hit) plus `/80` children under `2001:db8:abcd:1234::/64`.
fn build_ip6_rules(total: usize) -> Vec<IpMarkInfo> {
    assert!(total >= SMALL_RULES);
    let distract = flow_mark_from_raw(MARK_DISTRACT);
    let hit = flow_mark_from_raw(MARK_IP_HIT);

    let parse = |s: &str| IpAddr::V6(Ipv6Addr::from_str(s).unwrap());
    let mut rules = vec![
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8::"), prefix: 32 },
            priority: 500,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:ab00::"), prefix: 40 },
            priority: 400,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd::"), prefix: 48 },
            priority: 350,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1200::"), prefix: 56 },
            priority: 300,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1230::"), prefix: 60 },
            priority: 250,
        },
        IpMarkInfo {
            mark: hit,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234::"), prefix: 64 },
            priority: 200,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234:1000::"), prefix: 80 },
            priority: 150,
        },
        IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: parse("2001:db8:abcd:1234:8000::"), prefix: 80 },
            priority: 150,
        },
    ];

    for i in 0..(total - SMALL_RULES) {
        let seg2 = 0x2000u16.wrapping_add((i >> 8) as u16);
        let seg3 = (i & 0xff) as u16;
        let ip = Ipv6Addr::new(0x2001, 0x0db8, seg2, seg3, 0, 0, 0, 0);
        rules.push(IpMarkInfo {
            mark: distract,
            cidr: IpConfig { ip: IpAddr::V6(ip), prefix: 64 },
            priority: 300,
        });
    }
    assert_eq!(rules.len(), total);
    rules
}

fn build_dns6_rules(total: usize) -> Vec<FlowMarkInfo> {
    assert!(total >= 1);
    let mut rules = Vec::with_capacity(total);
    rules.push(FlowMarkInfo {
        ip: IpAddr::V6(cold_dns_dst_v6()),
        mark: MARK_DNS_WIN,
        priority: 50,
    });
    for i in 1..total {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0x9999, (i >> 16) as u16, i as u16, 0, 0, 1);
        rules.push(FlowMarkInfo {
            ip: IpAddr::V6(ip),
            mark: MARK_DISTRACT,
            priority: 100,
        });
    }
    rules
}

fn seed_ecmp_slots_v4(skel: &BenchRouteSkel<'_>) {
    let mut wan1 = RouteTargetInfo::dummy(WAN1_IFINDEX, "ppp0", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    wan1.mac = None;
    wan1.is_docker = false;
    wan1.gateway_ip = IpAddr::V4(WAN_GW_V4);

    let mut wan2 = RouteTargetInfo::dummy(WAN2_IFINDEX, "ppp1", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    wan2.mac = None;
    wan2.is_docker = false;
    wan2.gateway_ip = IpAddr::V4(WAN_GW_V4);

    for flow_id in [0u32, 2, 3, 4] {
        let single = [(WanRouteTarget::link(WAN1_LINK_CHAIN_ID, wan1.clone()), 1u32)];
        replace_wan_route_slots_v4_with_map(&skel.maps.rt4_slot_map, flow_id, &single);
    }
    // Dual-WAN ECMP 1:1 across 16 slots on Flow 5.
    let dual = [
        (WanRouteTarget::link(WAN1_LINK_CHAIN_ID, wan1), 1u32),
        (WanRouteTarget::link(WAN2_LINK_CHAIN_ID, wan2), 1u32),
    ];
    replace_wan_route_slots_v4_with_map(&skel.maps.rt4_slot_map, 5, &dual);
}

fn seed_ecmp_slots_v6(skel: &BenchRouteSkel<'_>) {
    let mut wan1 = RouteTargetInfo::dummy(WAN1_IFINDEX, "ppp0", IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    wan1.mac = None;
    wan1.is_docker = false;
    wan1.gateway_ip = IpAddr::V6(wan_gw_v6());

    let mut wan2 = RouteTargetInfo::dummy(WAN2_IFINDEX, "ppp1", IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    wan2.mac = None;
    wan2.is_docker = false;
    wan2.gateway_ip = IpAddr::V6(wan_gw_v6());

    for flow_id in [0u32, 2, 3, 4] {
        let single = [(WanRouteTarget::link(WAN1_LINK_CHAIN_ID, wan1.clone()), 1u32)];
        replace_wan_route_slots_v6_with_map(&skel.maps.rt6_slot_map, flow_id, &single);
    }
    let dual = [
        (WanRouteTarget::link(WAN1_LINK_CHAIN_ID, wan1), 1u32),
        (WanRouteTarget::link(WAN2_LINK_CHAIN_ID, wan2), 1u32),
    ];
    replace_wan_route_slots_v6_with_map(&skel.maps.rt6_slot_map, 5, &dual);
}

#[test]
#[ignore = "bench"]
fn route_v4_lookup_cost() {
    let pin_root = isolated_pin_root("bench-route-v4");
    let mut builder = BenchRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).expect("set pin_root_path");
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).expect("open bench_route");

    let gw_mac = MacAddr::from_str(GW_DST_MAC_STR).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().expect("bench_route rodata");
        rodata.egress_binding = wan_egress_binding {
            ifindex: LO_IFINDEX,
            wan_ip4: u32::from_ne_bytes(WAN_LOCAL_V4.octets()),
            wan_mask4: u32::from_ne_bytes(WAN_MASK_V4),
            gateway_ip4: u32::from_ne_bytes(WAN_GW_V4.octets()),
            source_mac: ROUTER_SRC_MAC,
            has_ipv4: 1,
            has_l2: 1,
            is_pppoe: 0,
            ..Default::default()
        };
        rodata.expected_gw_mac4 = gw_mac.octets();
    }

    let mut skel = open.load().expect("load bench_route");
    skel.maps.bss_data.as_deref_mut().expect("bench_route bss").confirmed_gateway_mac =
        mac_to_u64(gw_mac.octets());
    wire_prog(
        &skel.maps.bench_egress_chain,
        BENCH_EGRESS_SLOT_V4,
        &skel.progs.bench_wan_egress_l2_v4,
    );

    // 1. Seed WAN_CACHE (populated with distractors so WAN_CACHE miss is realistic)
    //    and LAN_CACHE (hot PPPoE L3 entry + hot Ethernet L2 entry + distractors).
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, WAN_CACHE);
    create_route4_cache_inner_map(&skel.maps.rt4_cache_map, LAN_CACHE);
    for i in 0..16u8 {
        put_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            WAN_CACHE,
            Ipv4Addr::new(192, 168, 200, i),
            Ipv4Addr::new(203, 0, 113, 100 + i),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
        put_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            Ipv4Addr::new(192, 168, 201, i),
            Ipv4Addr::new(203, 0, 113, 150 + i),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
    }
    seed_rt4_cache_entry(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        CLIENT_V4,
        HOT_PPPOE_DST_V4,
        WAN1_IFINDEX,
        false,
        MARK_CACHE_HIT,
        WAN1_LINK_CHAIN_ID,
    );
    seed_rt4_cache_entry(
        &skel.maps.rt4_cache_map,
        LAN_CACHE,
        CLIENT_V4,
        HOT_ETH_DST_V4,
        WAN1_IFINDEX,
        true,
        MARK_CACHE_HIT,
        WAN1_LINK_CHAIN_ID,
    );
    insert_ip_mac_v4(
        &skel.maps.ip_mac_v4,
        WAN_GW_V4,
        gw_mac,
        MacAddr::from_str(ROUTER_DEV_MAC_STR).unwrap(),
        LO_IFINDEX,
    );

    // 2. Seed local LAN subnets in `rt4_lan_map` (missed on WAN destinations).
    for vlan in [1u8, 101, 102, 105] {
        insert_route4_lan_entry(
            &skel.maps.rt4_lan_map,
            24,
            Ipv4Addr::new(192, 168, vlan, 0),
            Ipv4Addr::new(192, 168, vlan, 1),
            LAN_ROUTE_TYPE,
            LAN_IFINDEX,
            true,
            ROUTER_SRC_MAC,
        );
    }

    // 3. Seed `flow_match_map` (MAC fallback -> flow 1, /24 subnet -> flow 2, + distractors).
    //    Also seed `ROUTER_SRC_MAC` so Tier-2 E2E repeat iterations (2..REPEAT),
    //    which observe the rewritten source MAC, take the identical LPM hit path.
    seed_flow_match_mac(&skel.maps.flow_match_map, PKT_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_mac(&skel.maps.flow_match_map, ROUTER_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_subnet_v4(
        &skel.maps.flow_match_map,
        Ipv4Addr::new(192, 168, 101, 0),
        24,
        MATCHED_SRC_FLOW_ID,
    );
    for i in 0..16u8 {
        seed_flow_match_subnet_v4(
            &skel.maps.flow_match_map,
            Ipv4Addr::new(10, i, 0, 0),
            16,
            MAC_FALLBACK_FLOW_ID,
        );
    }

    // 4. Seed 16-slot ECMP `rt4_slot_map`.
    seed_ecmp_slots_v4(&skel);

    let hot_pppoe_pkt = simple_ipv4_tcp(CLIENT_V4, HOT_PPPOE_DST_V4);
    let hot_eth_pkt = simple_ipv4_tcp(CLIENT_V4, HOT_ETH_DST_V4);
    let cold_ip_pkt = simple_ipv4_tcp(CLIENT_V4, COLD_IP_DST_V4);
    let cold_dns_pkt = simple_ipv4_tcp(CLIENT_V4, COLD_DNS_DST_V4);
    let sink = &skel.maps.bench_sink;

    let base_v4 = measure_checked(&skel.progs.bench_route4_baseline, &hot_pppoe_pkt, 1, sink);
    let cache_pppoe_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cache_hit,
        &hot_pppoe_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cache_hit,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v4_e2e = measure_checked_e2e(
        &skel.progs.bench_route4_lan_cache_hit_e2e,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        gw_mac.octets(),
        sink,
    );

    // Small policy rule fill (8 IP prefixes + 8 DNS entries).
    create_inner_flow_match_map_v4(
        &skel.maps.flow4_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip4_rules(SMALL_RULES),
    )
    .expect("seed small flow4_ip_map");
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns4_rules(SMALL_RULES),
    );

    let cold_small_ip_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_small_dns_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_small_ip_v4_e2e = measure_checked_e2e(
        &skel.progs.bench_route4_lan_cold_resolve_e2e,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        gw_mac.octets(),
        sink,
    );
    let cold_small_dns_v4_e2e = measure_checked_e2e(
        &skel.progs.bench_route4_lan_cold_resolve_e2e,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        gw_mac.octets(),
        sink,
    );

    // Large policy rule fill (1024 IP prefixes + 1024 DNS entries).
    create_inner_flow_match_map_v4(
        &skel.maps.flow4_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip4_rules(LARGE_RULES),
    )
    .expect("seed 1k flow4_ip_map");
    create_flow_dns_inner_map_v4(
        &skel.maps.flow4_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns4_rules(LARGE_RULES),
    );

    let cold_1k_ip_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_1k_dns_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_full_1k_v4 = measure_checked(
        &skel.progs.bench_route4_lan_cold_full,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_1k_ip_v4_e2e = measure_checked_e2e(
        &skel.progs.bench_route4_lan_cold_resolve_e2e,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        gw_mac.octets(),
        sink,
    );
    let cold_1k_dns_v4_e2e = measure_checked_e2e(
        &skel.progs.bench_route4_lan_cold_resolve_e2e,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        gw_mac.octets(),
        sink,
    );

    println!("--- Route IPv4 baseline (kernel repeat={REPEAT}) ---");
    println!(
        "{:<28} per-pkt(min/med) {:>7.2}/{:>7.2} ns",
        "baseline_v4", base_v4.0 as f64, base_v4.1 as f64
    );
    println!("--- Route IPv4 lookup cost (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("lan_cache_hit_v4(pppoe)", cache_pppoe_v4, base_v4);
    report("lan_cache_hit_v4(eth_mac)", cache_eth_v4, base_v4);
    report("lan_cold_resolve_v4(8,ip)", cold_small_ip_v4, base_v4);
    report("lan_cold_resolve_v4(8,dns)", cold_small_dns_v4, base_v4);
    report("lan_cold_resolve_v4(1k,ip)", cold_1k_ip_v4, base_v4);
    report("lan_cold_resolve_v4(1k,dns)", cold_1k_dns_v4, base_v4);
    report("lan_cold_full_v4(1k,dns)", cold_full_1k_v4, base_v4);
    println!(
        "--- Route IPv4 Tier-2 E2E (lan_route -> wan_egress_l2, kernel repeat={REPEAT}, baseline-subtracted) ---"
    );
    report_e2e("lan_cache_hit_v4_e2e(eth)", cache_eth_v4_e2e, base_v4);
    report_e2e("lan_cold_resolve_v4_e2e(8,ip)", cold_small_ip_v4_e2e, base_v4);
    report_e2e("lan_cold_resolve_v4_e2e(8,dns)", cold_small_dns_v4_e2e, base_v4);
    report_e2e("lan_cold_resolve_v4_e2e(1k,ip)", cold_1k_ip_v4_e2e, base_v4);
    report_e2e("lan_cold_resolve_v4_e2e(1k,dns)", cold_1k_dns_v4_e2e, base_v4);
}

#[test]
#[ignore = "bench"]
fn route_v6_lookup_cost() {
    let pin_root = isolated_pin_root("bench-route-v6");
    let mut builder = BenchRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).expect("set pin_root_path");
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).expect("open bench_route");

    let client = client_v6();
    let hot_pppoe = hot_pppoe_dst_v6();
    let hot_eth = hot_eth_dst_v6();
    let cold_ip = cold_ip_dst_v6();
    let cold_dns = cold_dns_dst_v6();
    let gw6 = wan_gw_v6();
    let gw_mac = MacAddr::from_str(GW_DST_MAC_STR).unwrap();

    {
        let rodata = open.maps.rodata_data.as_deref_mut().expect("bench_route rodata");
        let mut wan_mask6 = [0u8; 16];
        wan_mask6[..8].fill(0xff);
        rodata.egress_binding = wan_egress_binding {
            ifindex: LO_IFINDEX,
            source_mac: ROUTER_SRC_MAC,
            has_l2: 1,
            is_pppoe: 0,
            wan_ip6: wan_local_v6().octets(),
            wan_mask6,
            gateway_ip6: gw6.octets(),
            has_ipv6: 1,
            ..Default::default()
        };
        rodata.expected_gw_mac6 = gw_mac.octets();
    }

    let mut skel = open.load().expect("load bench_route");
    skel.maps.bss_data.as_deref_mut().expect("bench_route bss").confirmed_gateway_mac6 =
        mac_to_u64(gw_mac.octets());
    wire_prog(
        &skel.maps.bench_egress_chain,
        BENCH_EGRESS_SLOT_V6,
        &skel.progs.bench_wan_egress_l2_v6,
    );

    // 1. Seed WAN_CACHE + LAN_CACHE for IPv6.
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, LAN_CACHE);
    for i in 0..16u16 {
        put_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            WAN_CACHE,
            Ipv6Addr::new(0xfd00, 0x200, 0, 0, 0, 0, 0, i + 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0x200, 0, 0, 0, 0, i + 1),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
        put_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            LAN_CACHE,
            Ipv6Addr::new(0xfd00, 0x201, 0, 0, 0, 0, 0, i + 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0x201, 0, 0, 0, 0, i + 1),
            WAN1_IFINDEX,
            false,
            MARK_DISTRACT,
        );
    }
    seed_rt6_cache_entry(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        client,
        hot_pppoe,
        WAN1_IFINDEX,
        false,
        MARK_CACHE_HIT,
        WAN1_LINK_CHAIN_ID,
    );
    seed_rt6_cache_entry(
        &skel.maps.rt6_cache_map,
        LAN_CACHE,
        client,
        hot_eth,
        WAN1_IFINDEX,
        true,
        MARK_CACHE_HIT,
        WAN1_LINK_CHAIN_ID,
    );

    // 2. Seed local LAN /64 prefixes in `rt6_lan_map`.
    for vlan in [1u16, 101, 102, 105] {
        insert_route6_lan_entry(
            &skel.maps.rt6_lan_map,
            64,
            Ipv6Addr::new(0xfd00, vlan, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xfd00, vlan, 0, 0, 0, 0, 0, 1),
            LAN_ROUTE_TYPE,
            LAN_IFINDEX,
            true,
            ROUTER_SRC_MAC,
        );
    }

    // 3. Seed `flow_match_map` (MAC fallback -> flow 1, /64 subnet -> flow 2, + distractors).
    //    Also seed `ROUTER_SRC_MAC` so Tier-2 E2E repeat iterations (2..REPEAT)
    //    observe the same MAC LPM hit path after the source MAC rewrite.
    seed_flow_match_mac(&skel.maps.flow_match_map, PKT_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_mac(&skel.maps.flow_match_map, ROUTER_SRC_MAC, MAC_FALLBACK_FLOW_ID);
    seed_flow_match_subnet_v6(
        &skel.maps.flow_match_map,
        Ipv6Addr::from_str("fd00:101::").unwrap(),
        64,
        MATCHED_SRC_FLOW_ID,
    );
    for i in 0..16u16 {
        seed_flow_match_subnet_v6(
            &skel.maps.flow_match_map,
            Ipv6Addr::new(0xfd00, 0x300 + i, 0, 0, 0, 0, 0, 0),
            64,
            MAC_FALLBACK_FLOW_ID,
        );
    }

    // 4. Seed 16-slot ECMP `rt6_slot_map`.
    seed_ecmp_slots_v6(&skel);

    let hot_pppoe_pkt = simple_ipv6_tcp_syn(client, hot_pppoe);
    let hot_eth_pkt = simple_ipv6_tcp_syn(client, hot_eth);
    let cold_ip_pkt = simple_ipv6_tcp_syn(client, cold_ip);
    let cold_dns_pkt = simple_ipv6_tcp_syn(client, cold_dns);
    let sink = &skel.maps.bench_sink;

    let base_v6 = measure_checked(&skel.progs.bench_route6_baseline, &hot_pppoe_pkt, 1, sink);
    let cache_pppoe_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cache_hit,
        &hot_pppoe_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cache_hit,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        sink,
    );
    let cache_eth_v6_e2e = measure_checked_e2e(
        &skel.progs.bench_route6_lan_cache_hit_e2e,
        &hot_eth_pkt,
        u64::from(MARK_CACHE_HIT),
        gw_mac.octets(),
        sink,
    );

    // Small policy rule fill (8 IPv6 prefixes + 8 DNS entries).
    create_inner_flow_match_map_v6(
        &skel.maps.flow6_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip6_rules(SMALL_RULES),
    )
    .expect("seed small flow6_ip_map");
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns6_rules(SMALL_RULES),
    );

    let cold_small_ip_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_small_dns_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_small_ip_v6_e2e = measure_checked_e2e(
        &skel.progs.bench_route6_lan_cold_resolve_e2e,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        gw_mac.octets(),
        sink,
    );
    let cold_small_dns_v6_e2e = measure_checked_e2e(
        &skel.progs.bench_route6_lan_cold_resolve_e2e,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        gw_mac.octets(),
        sink,
    );

    // Large policy rule fill (1024 IPv6 prefixes + 1024 DNS entries).
    create_inner_flow_match_map_v6(
        &skel.maps.flow6_ip_map,
        MATCHED_SRC_FLOW_ID,
        &build_ip6_rules(LARGE_RULES),
    )
    .expect("seed 1k flow6_ip_map");
    create_flow_dns_inner_map_v6(
        &skel.maps.flow6_dns_map,
        MATCHED_SRC_FLOW_ID,
        &build_dns6_rules(LARGE_RULES),
    );

    let cold_1k_ip_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        sink,
    );
    let cold_1k_dns_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_resolve,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_full_1k_v6 = measure_checked(
        &skel.progs.bench_route6_lan_cold_full,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        sink,
    );
    let cold_1k_ip_v6_e2e = measure_checked_e2e(
        &skel.progs.bench_route6_lan_cold_resolve_e2e,
        &cold_ip_pkt,
        u64::from(MARK_IP_HIT),
        gw_mac.octets(),
        sink,
    );
    let cold_1k_dns_v6_e2e = measure_checked_e2e(
        &skel.progs.bench_route6_lan_cold_resolve_e2e,
        &cold_dns_pkt,
        u64::from(MARK_DNS_WIN),
        gw_mac.octets(),
        sink,
    );

    println!("--- Route IPv6 baseline (kernel repeat={REPEAT}) ---");
    println!(
        "{:<28} per-pkt(min/med) {:>7.2}/{:>7.2} ns",
        "baseline_v6", base_v6.0 as f64, base_v6.1 as f64
    );
    println!("--- Route IPv6 lookup cost (kernel repeat={REPEAT}, baseline-subtracted) ---");
    report("lan_cache_hit_v6(pppoe)", cache_pppoe_v6, base_v6);
    report("lan_cache_hit_v6(eth_mac)", cache_eth_v6, base_v6);
    report("lan_cold_resolve_v6(8,ip)", cold_small_ip_v6, base_v6);
    report("lan_cold_resolve_v6(8,dns)", cold_small_dns_v6, base_v6);
    report("lan_cold_resolve_v6(1k,ip)", cold_1k_ip_v6, base_v6);
    report("lan_cold_resolve_v6(1k,dns)", cold_1k_dns_v6, base_v6);
    report("lan_cold_full_v6(1k,dns)", cold_full_1k_v6, base_v6);
    println!(
        "--- Route IPv6 Tier-2 E2E (lan_route -> wan_egress_l2, kernel repeat={REPEAT}, baseline-subtracted) ---"
    );
    report_e2e("lan_cache_hit_v6_e2e(eth)", cache_eth_v6_e2e, base_v6);
    report_e2e("lan_cold_resolve_v6_e2e(8,ip)", cold_small_ip_v6_e2e, base_v6);
    report_e2e("lan_cold_resolve_v6_e2e(8,dns)", cold_small_dns_v6_e2e, base_v6);
    report_e2e("lan_cold_resolve_v6_e2e(1k,ip)", cold_1k_ip_v6_e2e, base_v6);
    report_e2e("lan_cold_resolve_v6_e2e(1k,dns)", cold_1k_dns_v6_e2e, base_v6);
}
