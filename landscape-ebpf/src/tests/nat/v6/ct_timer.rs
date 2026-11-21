use std::{cell::RefCell, mem::MaybeUninit};

use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, RingBufferBuilder,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    maps::{Nat6TimerKey, Nat6TimerValue},
    tests::{
        isolated_pin_root,
        nat::test_nat6_v3::{TestNat6V3Skel, TestNat6V3SkelBuilder},
    },
};

const ACTIVE: u64 = 20;
const TIMEOUT_1: u64 = 30;
const TIMEOUT_2: u64 = 31;
const RELEASE: u64 = 40;
const CLEAN_START: u64 = 50;

fn tick_ms(skel: &TestNat6V3Skel<'_>) -> u32 {
    let packet = [0; 64];
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

    let key = Nat6TimerKey { l4_protocol: 17, ..Default::default() };
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
    for (delay, status) in [(1000, TIMEOUT_1), (1000, TIMEOUT_2), (300_000, RELEASE)] {
        assert_eq!(tick_ms(&skel), delay);
        assert_eq!(read().unwrap().status, status);
    }

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
