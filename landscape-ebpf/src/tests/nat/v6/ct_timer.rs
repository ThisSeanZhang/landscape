use std::{cell::RefCell, mem::MaybeUninit, net::Ipv6Addr, time::Duration};

use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut, RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    maps::{Nat6MappingKey, Nat6MappingValue, Nat6TimerKey, Nat6TimerValue},
    tests::{
        TestSkb,
        helper::net::wait_for,
        isolated_pin_root,
        nat::test_nat6_v3::{TestNat6V3Skel, TestNat6V3SkelBuilder},
    },
};

const ACTIVE: u64 = 20;
const IDLE_CHECK_1: u64 = 30;
const IDLE_CHECK_2: u64 = 31;
const WAIT_TIMEOUT: u64 = 40;
const CLEAN_START: u64 = 50;

fn run(prog: &ProgramMut<'_>) -> u32 {
    let packet = [0; 64];
    prog.test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .unwrap()
        .return_value
}

fn tick_ms(skel: &TestNat6V3Skel<'_>) -> u32 {
    let key = Nat6TimerKey {
        local: Nat6MappingKey { l4_protocol: 17, ..Default::default() },
        ..Default::default()
    };
    tick_key(skel, &key)
}

fn tick_key(skel: &TestNat6V3Skel<'_>, key: &Nat6TimerKey) -> u32 {
    let mut packet = [0; 64];
    packet[14..14 + size_of::<Nat6TimerKey>()].copy_from_slice(key.as_bytes());
    skel.progs
        .nat6_report_tick
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .unwrap()
        .return_value
}

fn check_report_pressure(drain_after_failures: Option<usize>) {
    let pin_root = isolated_pin_root("nat6-ct-report");
    let mut builder = TestNat6V3SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut object = MaybeUninit::uninit();
    let mut open = builder.open(&mut object).unwrap();
    open.maps.nat_metric_events.set_max_entries(4096).unwrap();
    let skel = open.load().unwrap();
    let events = RefCell::new(Vec::new());
    let mut ring = RingBufferBuilder::new();
    ring.add(&skel.maps.nat_metric_events, |data| {
        let Ok(event) = ConnectMetric::try_from(data) else { return -libc::EINVAL };
        events.borrow_mut().push(event);
        0
    })
    .unwrap();
    let ring = ring.build().unwrap();
    let drain = || {
        ring.consume().unwrap();
        events.take()
    };

    let key = Nat6TimerKey {
        local: Nat6MappingKey { l4_protocol: 17, ..Default::default() },
        ..Default::default()
    };
    let ct = &skel.maps.nat6_timer_map;
    let seed = |tag| {
        let value = Nat6TimerValue {
            status: ACTIVE,
            create_time: tag,
            ..Default::default()
        };
        ct.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY).unwrap();
    };
    let read = || {
        ct.lookup(key.as_bytes(), MapFlags::ANY)
            .unwrap()
            .map(|raw| Nat6TimerValue::read_from_bytes(&raw).unwrap())
    };

    let max_events =
        skel.maps.nat_metric_events.max_entries() as usize / size_of::<ConnectMetric>();
    for _ in 0..=max_events {
        seed(1);
        assert_eq!(tick_ms(&skel), 1000);
    }
    seed(2);
    for (delay, status) in [(1000, IDLE_CHECK_1), (1000, IDLE_CHECK_2), (300_000, WAIT_TIMEOUT)] {
        assert_eq!(tick_ms(&skel), delay);
        assert_eq!(read().unwrap().status, status);
    }
    // Advance the disarmed entry to expiry before exercising the DELETE retries.
    let mut expired = read().unwrap();
    expired.wait_deadline_ns = 1;
    ct.update(key.as_bytes(), expired.as_bytes(), MapFlags::EXIST).unwrap();

    let retries = drain_after_failures.unwrap_or(2);
    for (attempt, delay) in [10, 20].into_iter().take(retries).enumerate() {
        assert_eq!(tick_ms(&skel), delay);
        let pending = read().unwrap();
        assert_eq!(
            (pending.status, pending.delete_report_failures),
            (CLEAN_START, attempt as u8 + 1)
        );
    }
    let drain_full_ring = || {
        let active = drain();
        assert!(!active.is_empty());
        assert!(
            active
                .iter()
                .all(|e| e.create_time == 1 && e.status_type() == ConnectStatusType::Active)
        );
    };
    if drain_after_failures.is_some() {
        drain_full_ring();
    }
    assert_eq!(tick_ms(&skel), 0);
    assert!(read().is_none());
    if drain_after_failures.is_some() {
        let final_events = drain();
        assert_eq!(final_events.len(), 1);
        assert_eq!(final_events[0].create_time, 2);
        assert_eq!(final_events[0].status_type(), ConnectStatusType::Disabled);
    } else {
        drain_full_ring();
    }
}

#[test]
fn full_metric_ring_allows_aging_and_bounds_delete_attempts() {
    check_report_pressure(None);
}

#[test]
fn delete_removes_ct_as_soon_as_the_report_succeeds() {
    for failures in 0..=2 {
        check_report_pressure(Some(failures));
    }
}

#[test]
fn packets_only_arm_the_long_wait_and_stale_wakeups_preserve_its_deadline() {
    let pin_root = isolated_pin_root("nat6-ct-wakeup");
    let mut builder = TestNat6V3SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut object = MaybeUninit::uninit();
    let mut open = builder.open(&mut object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().REPORT_INTERVAL = 100_000_000;
    let skel = open.load().unwrap();
    let ct = &skel.maps.nat6_timer_map;
    let key = Nat6TimerKey {
        local: Nat6MappingKey { l4_protocol: 17, ..Default::default() },
        ..Default::default()
    };
    let read = || {
        let raw = ct.lookup(key.as_bytes(), MapFlags::ANY).unwrap().expect("CT still present");
        Nat6TimerValue::read_from_bytes(&raw).unwrap()
    };
    for (status, expected, armed) in [
        (0, ACTIVE, 0),
        (ACTIVE, ACTIVE, 0),
        (IDLE_CHECK_1, ACTIVE, 0),
        (IDLE_CHECK_2, ACTIVE, 0),
        (CLEAN_START, CLEAN_START, 0),
        (WAIT_TIMEOUT, ACTIVE, 1),
    ] {
        let value = Nat6TimerValue { status, ..Default::default() };
        ct.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY).unwrap();
        assert_eq!(run(&skel.progs.nat6_packet_wakeup), armed, "starting status {status}");
        assert_eq!(read().status, expected);
    }

    let value = Nat6TimerValue { status: WAIT_TIMEOUT, ..Default::default() };
    ct.update(key.as_bytes(), value.as_bytes(), MapFlags::EXIST).unwrap();
    assert_eq!(run(&skel.progs.nat6_rearm_idle_wait), 0);
    wait_for("active ticks after stale idle rearm", Duration::from_secs(3), || {
        let value = read();
        value.status == WAIT_TIMEOUT && value.wait_deadline_ns != 0
    });
    let deadline = read().wait_deadline_ns;
    let remaining_ms = tick_ms(&skel);
    assert!((1..300_000).contains(&remaining_ms));
    let waiting = read();
    assert_eq!((waiting.status, waiting.wait_deadline_ns), (WAIT_TIMEOUT, deadline));
}

#[test]
fn shared_mapping_outlives_its_trigger_and_failed_ct_creation() {
    let root = isolated_pin_root("nat6-mapping-release");
    let mut builder = TestNat6V3SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut object = MaybeUninit::uninit();
    let mut open = builder.open(&mut object).unwrap();
    open.maps.nat6_timer_map.set_max_entries(2).unwrap();
    let ro = open.maps.rodata_data.as_deref_mut().unwrap();
    let wan: Ipv6Addr = "2001:db8:a::10".parse().unwrap();
    ro.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan));
    ro.REPORT_INTERVAL = 60_000_000_000; // Drive the production timer steps explicitly.
    let skel = open.load().unwrap();
    let lan: Ipv6Addr = "fd00:1::10".parse().unwrap();
    let a: Ipv6Addr = "2001:db8:b::1".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:b::2".parse().unwrap();
    let packet = |egress, peer: Ipv6Addr, port| {
        let (src, dst, sport, dport, prog) = if egress {
            (lan, peer, 12345, port, &skel.progs.handle_ipv6_egress)
        } else {
            (peer, wan, port, 12345, &skel.progs.handle_ipv6_ingress)
        };
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv6(src.octets(), dst.octets(), 64)
            .udp(sport, dport)
            .write(&mut frame, &[])
            .unwrap();
        let mut ctx = TestSkb { mark: 0x8000, ..Default::default() };
        prog.test_run(ProgramInput {
            data_in: Some(&frame),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .unwrap()
        .return_value as i32
    };
    let local = Nat6MappingKey {
        client_suffix: lan.octets()[8..].try_into().unwrap(),
        client_port: 12345u16.to_be(),
        l4_protocol: 17,
        ..Default::default()
    };
    let key = |peer: Ipv6Addr| Nat6TimerKey {
        local,
        remote_addr: peer.octets(),
        remote_port: 53u16.to_be(),
        _pad: 0,
    };
    let mapping = || {
        skel.maps
            .nat6_mapping_map
            .lookup(local.as_bytes(), MapFlags::ANY)
            .unwrap()
            .map(|v| Nat6MappingValue::read_from_bytes(&v).unwrap())
    };
    let ct = &skel.maps.nat6_timer_map;
    let expire = |key: &Nat6TimerKey| {
        let raw = ct.lookup(key.as_bytes(), MapFlags::ANY).unwrap().unwrap();
        let mut value = Nat6TimerValue::read_from_bytes(&raw).unwrap();
        value.status = WAIT_TIMEOUT;
        value.wait_deadline_ns = 1;
        ct.update(key.as_bytes(), value.as_bytes(), MapFlags::EXIST).unwrap();
        assert_eq!(tick_key(&skel, key), 0);
        assert!(ct.lookup(key.as_bytes(), MapFlags::ANY).unwrap().is_none());
    };
    let events = RefCell::new(Vec::new());
    let mut ring = RingBufferBuilder::new();
    ring.add(&skel.maps.nat_metric_events, |raw| {
        events.borrow_mut().push(ConnectMetric::try_from(raw).unwrap());
        0
    })
    .unwrap();
    let ring = ring.build().unwrap();
    assert_eq!(packet(false, a, 53), 2); // Dynamic ingress requires an existing mapping.
    assert_eq!(packet(true, a, 53), -1);
    assert_eq!(packet(false, b, 53), -1);
    assert_eq!(packet(true, b, 53), -1);
    assert_eq!(packet(true, a, 54), 2); // CT table is full. Roll back the acquired reference.
    assert_eq!(mapping().unwrap().refs, 2);
    expire(&key(a));
    let shared = mapping().unwrap();
    assert_eq!((shared.refs, shared.trigger_addr), (1, a.octets()));
    assert_eq!(packet(false, b, 53), -1);
    expire(&key(b));
    assert!(mapping().is_none());
    assert_eq!(ct.keys().count(), 0);
    ring.consume().unwrap();
    let reports = events.take();
    assert_eq!(reports.len(), 2);
    for (event, (peer, ingress)) in reports.iter().zip([(a, 0), (b, 2)]) {
        assert_eq!(event.status_type(), ConnectStatusType::Disabled);
        assert_eq!((event.dst_addr, event.dst_port), (peer.octets(), 53));
        assert_eq!((event.egress_packets, event.ingress_packets), (1, ingress));
    }
}
