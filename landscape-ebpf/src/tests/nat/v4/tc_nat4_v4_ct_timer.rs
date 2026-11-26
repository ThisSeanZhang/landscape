use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

pub(crate) mod test_nat4_v4_ct_timer {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_nat4_v4_ct_timer.skel.rs"));
}

use test_nat4_v4_ct_timer::{TestNat4V4CtTimerSkel, TestNat4V4CtTimerSkelBuilder, types};

const PROTO_UDP: u8 = 17;
const PROTO_TCP: u8 = 6;

const KIND_FREE: u8 = 0;
const KIND_DYNAMIC: u8 = 1;
const KIND_STATIC: u8 = 2;

const STATE_SHIFT: u64 = 56;
const STATE_ACTIVE: u64 = 1;
const STATE_CLOSED: u64 = 2;

const CT_READY: u64 = 0;
const CT_ACQUIRE_REF: u64 = 10;
const CT_ACTIVE: u64 = 20;
const CT_IDLE_CHECK_1: u64 = 30;
const CT_IDLE_CHECK_2: u64 = 31;
const CT_WAIT_TIMEOUT: u64 = 40;
const CT_WAIT_TCP_CLOSE: u64 = 41;
const CT_RELEASE_REF: u64 = 49;
const CT_DELETE_LAN_MAPPING: u64 = 50;
const CT_CLEAR_WAN_SLOT: u64 = 51;
const CT_RETURN_PORT: u64 = 52;
const CT_RETRY_DELETE_REPORT: u64 = 53;
const TCP_SYN: u8 = 1;
const TCP_ACK: u8 = 2;
const TCP_FIN: u8 = 3;
const TCP_RST: u8 = 4;
const TCP_SYN_ACK: u8 = 5;

const LAN_SYN: u64 = 1;
const WAN_SYN: u64 = 2;
const BOTH_SYN: u64 = LAN_SYN | WAN_SYN;

const STEP_DELETE_CT: u32 = 1;
const STEP_RESTART: u32 = 2;

const REPORT_INTERVAL: u64 = 1_000_000_000;
const TCP_SYN_TIMEOUT: u64 = 6_000_000_000;
const TCP_CLOSE_TIMEOUT: u64 = 6_000_000_000;
const TCP_TIMEOUT: u64 = 600_000_000_000;
const UDP_TIMEOUT: u64 = 300_000_000_000;
const CLEAN_STEP_NS: u64 = 1_000;
const CLEAN_RETRY_MAX_NS: u64 = 100_000_000;

const LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(50, 18, 88, 205);
const LAN_PORT: u16 = 56186;
const REMOTE_PORT: u16 = 443;
const NAT_PORT: u16 = 40000;
const GENERATION: u32 = 7;

fn be32(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

fn state_ref(state: u64, refs: u64) -> u64 {
    (state << STATE_SHIFT) | refs
}

fn ct_key(proto: u8) -> types::napt_ct_key {
    types::napt_ct_key {
        internal_addr: be32(LAN_IP),
        remote_addr: be32(REMOTE_IP),
        internal_port: LAN_PORT.to_be(),
        remote_port: if proto == 1 { 0 } else { REMOTE_PORT.to_be() },
        proto,
        pad: [0; 3],
    }
}

fn lan_key(proto: u8) -> types::napt_from_lan_key {
    types::napt_from_lan_key {
        internal_addr: be32(LAN_IP),
        internal_port: LAN_PORT.to_be(),
        proto,
        pad: 0,
    }
}

fn lan_value(kind: u8, generation: u32) -> types::napt_from_lan_value {
    types::napt_from_lan_value {
        external_port: NAT_PORT.to_be(),
        kind,
        allow_reuse: 1,
        generation,
        trigger_addr: be32(REMOTE_IP),
        trigger_port: REMOTE_PORT.to_be(),
        pad: 0,
    }
}

fn wan_value(kind: u8, generation: u32, state_ref_: u64) -> types::napt_from_wan_value {
    types::napt_from_wan_value {
        internal_addr: be32(LAN_IP),
        internal_port: LAN_PORT.to_be(),
        kind,
        allow_reuse: 1,
        trigger_addr: be32(REMOTE_IP),
        trigger_port: REMOTE_PORT.to_be(),
        pad0: 0,
        generation,
        pad1: 0,
        state_ref: state_ref_,
    }
}

fn ct_value(status: u64, generation: u32, is_static: u8) -> types::napt_ct_value {
    types::napt_ct_value {
        external_port: NAT_PORT.to_be(),
        is_static,
        pad0: 0,
        from_wan_gen: generation,
        status,
        tcp_flags: BOTH_SYN,
        ..Default::default()
    }
}

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

fn wan_index(proto: u8, port: u16) -> u32 {
    let base = match proto {
        PROTO_UDP => 0,
        PROTO_TCP => 65536,
        1 => 131072,
        _ => panic!("bad proto"),
    };
    base + u32::from(port)
}

fn put_wan<M: MapCore>(map: &M, proto: u8, value: &types::napt_from_wan_value) {
    let key = wan_index(proto, NAT_PORT).to_ne_bytes();
    map.update(&key, as_bytes(value), MapFlags::ANY).unwrap();
}

fn put_lan<M: MapCore>(map: &M, proto: u8, value: &types::napt_from_lan_value) {
    let key = lan_key(proto);
    map.update(as_bytes(&key), as_bytes(value), MapFlags::ANY).unwrap();
}

fn put_ct<M: MapCore>(map: &M, proto: u8, value: &types::napt_ct_value) {
    let key = ct_key(proto);
    map.update(as_bytes(&key), as_bytes(value), MapFlags::ANY).unwrap();
}

fn with_skel<R>(f: impl FnOnce(&TestNat4V4CtTimerSkel<'_>) -> R) -> R {
    let builder = TestNat4V4CtTimerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();
    f(&skel)
}

fn run_step(
    skel: &TestNat4V4CtTimerSkel<'_>,
    proto: u8,
    force_queue_push_fail: bool,
) -> types::napt_ct_timer_test_result {
    run_step_with_input(
        skel,
        types::napt_ct_timer_test_input {
            key: ct_key(proto),
            force_queue_push_fail: force_queue_push_fail as u8,
            ..Default::default()
        },
    )
}

fn run_step_with_input(
    skel: &TestNat4V4CtTimerSkel<'_>,
    input: types::napt_ct_timer_test_input,
) -> types::napt_ct_timer_test_result {
    let key = 0u32;
    skel.maps
        .napt_ct_timer_test_input
        .update(as_bytes(&key), as_bytes(&input), MapFlags::ANY)
        .unwrap();

    let data = vec![0u8; 64];
    let input = ProgramInput { data_in: Some(&data), ..Default::default() };
    let ret =
        skel.progs.napt_ct_timer_step_test.test_run(input).expect("test_run failed").return_value
            as i32;
    assert_eq!(ret, 0);

    let bytes = skel
        .maps
        .napt_ct_timer_test_result
        .lookup(as_bytes(&key), MapFlags::ANY)
        .unwrap()
        .expect("missing result");
    read_unaligned::<types::napt_ct_timer_test_result>(&bytes)
}

fn run_advance(
    skel: &TestNat4V4CtTimerSkel<'_>,
    proto: u8,
    tcp_phase: u8,
    gress: u8,
) -> types::napt_ct_timer_test_result {
    let input =
        types::napt_ct_advance_test_input { key: ct_key(proto), tcp_phase, gress, pad: [0; 2] };
    let key = 0u32;
    skel.maps
        .napt_ct_advance_test_input
        .update(as_bytes(&key), as_bytes(&input), MapFlags::ANY)
        .unwrap();

    let data = vec![0u8; 64];
    let input = ProgramInput { data_in: Some(&data), ..Default::default() };
    let ret = skel.progs.napt_ct_advance_test.test_run(input).expect("test_run failed").return_value
        as i32;
    assert_eq!(ret, 0);

    let bytes = skel
        .maps
        .napt_ct_timer_test_result
        .lookup(as_bytes(&key), MapFlags::ANY)
        .unwrap()
        .expect("missing result");
    read_unaligned::<types::napt_ct_timer_test_result>(&bytes)
}

fn run_resolve(
    skel: &TestNat4V4CtTimerSkel<'_>,
    proto: u8,
    mapping_gen: u32,
    mapping_kind: u8,
) -> types::napt_ct_timer_test_result {
    let input = types::napt_ct_resolve_test_input {
        key: ct_key(proto),
        r#gen: mapping_gen,
        kind: mapping_kind,
        pad: [0; 3],
    };
    let key = 0u32;
    skel.maps
        .napt_ct_resolve_test_input
        .update(as_bytes(&key), as_bytes(&input), MapFlags::ANY)
        .unwrap();

    let data = vec![0u8; 64];
    let input = ProgramInput { data_in: Some(&data), ..Default::default() };
    let ret = skel.progs.napt_ct_resolve_test.test_run(input).expect("test_run failed").return_value
        as i32;
    assert_eq!(ret, 0);

    let bytes = skel
        .maps
        .napt_ct_timer_test_result
        .lookup(as_bytes(&key), MapFlags::ANY)
        .unwrap()
        .expect("missing result");
    read_unaligned::<types::napt_ct_timer_test_result>(&bytes)
}

fn lookup_wan<M: MapCore>(map: &M, proto: u8) -> Option<types::napt_from_wan_value> {
    let key = wan_index(proto, NAT_PORT).to_ne_bytes();
    map.lookup(&key, MapFlags::ANY).unwrap().map(|bytes| read_unaligned(&bytes))
}

fn assert_dynamic_mapping(skel: &TestNat4V4CtTimerSkel<'_>, state: u64, refs: u64) {
    let wan = lookup_wan(&skel.maps.napt_from_wan, PROTO_UDP).unwrap();
    assert_eq!(wan.kind, KIND_DYNAMIC);
    assert_eq!(wan.generation, GENERATION);
    assert_eq!(wan.state_ref, state_ref(state, refs));
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use libbpf_rs::RingBufferBuilder;
    use std::cell::RefCell;

    fn fill_metric_ring(skel: &TestNat4V4CtTimerSkel<'_>) {
        let max_reports =
            skel.maps.nat_metric_events.max_entries() as usize / size_of::<ConnectMetric>();
        for _ in 0..=max_reports {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, GENERATION, 0));
            run_step(skel, PROTO_TCP, false);
        }
    }

    fn with_full_metric_ring(
        test: impl FnOnce(&TestNat4V4CtTimerSkel<'_>, &dyn Fn() -> Vec<ConnectMetric>),
    ) {
        let mut object = MaybeUninit::uninit();
        let mut open = TestNat4V4CtTimerSkelBuilder::default().open(&mut object).unwrap();
        open.maps.nat_metric_events.set_max_entries(4096).unwrap();
        let skel = open.load().unwrap();
        let metrics = &skel.maps.nat_metric_events;
        let reports = RefCell::new(Vec::new());
        let mut builder = RingBufferBuilder::new();
        builder
            .add(metrics, |data| {
                let Ok(event) = ConnectMetric::try_from(data) else { return -libc::EINVAL };
                reports.borrow_mut().push(event);
                0
            })
            .unwrap();
        let ring = builder.build().unwrap();
        fill_metric_ring(&skel);
        test(&skel, &|| {
            ring.consume().unwrap();
            reports.take()
        });
    }

    #[test]
    fn full_metric_ring_does_not_delay_ct_aging() {
        with_full_metric_ring(|skel, drain| {
            let ticks = [
                (CT_IDLE_CHECK_1, REPORT_INTERVAL),
                (CT_IDLE_CHECK_2, REPORT_INTERVAL),
                (CT_WAIT_TIMEOUT, UDP_TIMEOUT),
            ];
            let age_ct = || {
                put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_ACTIVE, GENERATION, 0));
                for (status, delay) in ticks {
                    let step = run_step(skel, PROTO_UDP, false);
                    assert_eq!(
                        (step.action, step.status, step.next_timeout),
                        (STEP_RESTART, status, delay)
                    );
                }
            };

            age_ct();
            let reports = drain();
            assert!(!reports.is_empty() && reports.iter().all(|e| e.l4_proto == PROTO_TCP));

            age_ct();
            assert_eq!(drain().len(), ticks.len());
        });
    }

    #[test]
    fn full_metric_ring_drops_delete_after_three_attempts() {
        with_full_metric_ring(|skel, drain| {
            // Shared, static and stale CTs release only their own resources before retrying.
            for (kind, generation, refs, remaining_refs) in [
                (KIND_DYNAMIC, GENERATION, 2, 1),
                (KIND_STATIC, GENERATION, 0, 0),
                (KIND_DYNAMIC, GENERATION + 1, 1, 1),
            ] {
                put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(kind, generation));
                put_wan(
                    &skel.maps.napt_from_wan,
                    PROTO_UDP,
                    &wan_value(kind, generation, state_ref(STATE_ACTIVE, refs)),
                );
                put_ct(
                    &skel.maps.napt_ct,
                    PROTO_UDP,
                    &ct_value(CT_WAIT_TIMEOUT, GENERATION, u8::from(kind == KIND_STATIC)),
                );
                for delay in [10_000_000, 20_000_000] {
                    let step = run_step(skel, PROTO_UDP, false);
                    assert_eq!(
                        (step.action, step.status, step.next_timeout),
                        (STEP_RESTART, CT_RETRY_DELETE_REPORT, delay)
                    );
                    assert_eq!(
                        (step.kind, step.r#gen, step.state_ref),
                        (kind, generation, state_ref(STATE_ACTIVE, remaining_refs))
                    );
                }
                let done = run_step(skel, PROTO_UDP, false);
                assert_eq!(
                    (done.action, done.timer_exists, done.lan_exists),
                    (STEP_DELETE_CT, 0, 1)
                );
                assert_eq!(
                    (done.kind, done.r#gen, done.state_ref),
                    (kind, generation, state_ref(STATE_ACTIVE, remaining_refs))
                );
                assert!(skel.maps.napt_udp_ports.lookup_and_delete(&[]).unwrap().is_none());
            }
            let reports = drain();
            assert!(
                !reports.is_empty()
                    && reports.iter().all(|e| e.status_type() == ConnectStatusType::Active)
            );
        });
    }

    #[test]
    fn delete_report_stops_after_first_successful_retry() {
        with_full_metric_ring(|skel, drain| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_WAIT_TIMEOUT, GENERATION, 1));
            let pending = run_step(skel, PROTO_UDP, false);
            assert_eq!(
                (pending.status, pending.next_timeout),
                (CT_RETRY_DELETE_REPORT, 10_000_000)
            );
            assert!(!drain().is_empty());

            let done = run_step(skel, PROTO_UDP, false);
            assert_eq!((done.action, done.timer_exists), (STEP_DELETE_CT, 0));
            let reports = drain();
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].status_type(), ConnectStatusType::Disabled);
        });
    }

    #[test]
    fn delete_report_retry_succeeds_after_another_flow_reuses_the_port() {
        use super::super::common::{WAN_IP, parse_udp, run, udp_pkt};
        use crate::tests::tc_nat4_v4_skel::TcNat4V4SkelBuilder;
        use std::os::fd::AsFd;

        with_full_metric_ring(|skel, drain| {
            let mut object = MaybeUninit::uninit();
            let mut open = TcNat4V4SkelBuilder::default().open(&mut object).unwrap();
            let config = open.maps.rodata_data.as_deref_mut().unwrap();
            config.current_l3_offset = 14;
            config.land_nat_external_addr = be32(WAN_IP);
            open.maps.napt_ct.reuse_fd(skel.maps.napt_ct.as_fd()).unwrap();
            open.maps.napt_from_lan.reuse_fd(skel.maps.napt_from_lan.as_fd()).unwrap();
            open.maps.napt_from_wan.reuse_fd(skel.maps.napt_from_wan.as_fd()).unwrap();
            open.maps.napt_udp_ports.reuse_fd(skel.maps.napt_udp_ports.as_fd()).unwrap();
            let tc = open.load().unwrap();

            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 1)),
            );
            let mut old = ct_value(CT_WAIT_TIMEOUT, GENERATION, 0);
            old.create_time = 12345;
            old.ingress_bytes = 456;
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &old);
            for status in [CT_DELETE_LAN_MAPPING, CT_CLEAR_WAN_SLOT, CT_RETURN_PORT] {
                let step = run_step(skel, PROTO_UDP, false);
                assert_eq!((step.status, step.next_timeout), (status, CLEAN_STEP_NS));
            }
            let blocked = run_step(skel, PROTO_UDP, true);
            assert_eq!((blocked.status, blocked.queue_push_ret), (CT_RETURN_PORT, -1));
            let pending = run_step(skel, PROTO_UDP, false);
            assert_eq!(
                (pending.status, pending.queue_push_ret, pending.next_timeout),
                (CT_RETRY_DELETE_REPORT, 0, 10_000_000)
            );

            let packet = udp_pkt(LAN_IP, REMOTE_IP, LAN_PORT, REMOTE_PORT + 1);
            let (action, out) = run(&tc.progs.tc_v4_from_lan, &packet);
            assert_eq!(action, -1); // TC_ACT_UNSPEC
            let out = parse_udp(&out);
            assert_eq!((out.src, out.sport), (WAN_IP, NAT_PORT));
            let lookup = run_resolve(skel, PROTO_UDP, GENERATION + 1, KIND_DYNAMIC);
            assert_eq!((lookup.action, lookup.timer_exists), (0, 1));

            let retry = run_step(skel, PROTO_UDP, false);
            assert_eq!((retry.status, retry.next_timeout), (CT_RETRY_DELETE_REPORT, 20_000_000));
            assert!(drain().iter().all(|e| e.status_type() == ConnectStatusType::Active));
            let done = run_step(skel, PROTO_UDP, false);
            assert_eq!((done.action, done.timer_exists, done.lan_exists), (STEP_DELETE_CT, 0, 1));
            assert_eq!(
                (done.kind, done.r#gen, done.state_ref),
                (KIND_DYNAMIC, GENERATION + 1, state_ref(STATE_ACTIVE, 1))
            );
            assert!(skel.maps.napt_udp_ports.lookup_and_delete(&[]).unwrap().is_none());
            let reports = drain();
            assert_eq!(reports.len(), 1);
            let report = &reports[0];
            assert_eq!(report.status_type(), ConnectStatusType::Disabled);
            assert_eq!(
                (report.dst_port, report.create_time, report.ingress_bytes),
                (REMOTE_PORT, old.create_time, old.ingress_bytes)
            );
        });
    }

    #[test]
    fn active_transitions_to_idle_check_1() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_ACTIVE, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_IDLE_CHECK_1);
            assert_eq!(result.next_timeout, REPORT_INTERVAL);
        });
    }

    #[test]
    fn idle_check_1_transitions_to_idle_check_2() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_IDLE_CHECK_1, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_IDLE_CHECK_2);
            assert_eq!(result.next_timeout, REPORT_INTERVAL);
        });
    }

    #[test]
    fn idle_check_2_enters_wait_timeout_with_udp_timeout() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_IDLE_CHECK_2, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_WAIT_TIMEOUT);
            assert_eq!(result.next_timeout, UDP_TIMEOUT);
        });
    }

    #[test]
    fn idle_check_2_tcp_syn_uses_tcp_timeout() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_IDLE_CHECK_2, GENERATION, 0));
            let result = run_step(skel, PROTO_TCP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_WAIT_TIMEOUT);
            assert_eq!(result.next_timeout, TCP_TIMEOUT);
        });
    }

    #[test]
    fn idle_check_2_tcp_incomplete_handshake_uses_syn_timeout() {
        with_skel(|skel| {
            let mut value = ct_value(CT_IDLE_CHECK_2, GENERATION, 0);
            value.tcp_flags = LAN_SYN;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_step(skel, PROTO_TCP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_WAIT_TIMEOUT);
            assert_eq!(result.next_timeout, TCP_SYN_TIMEOUT);
        });
    }

    #[test]
    fn tcp_half_close_keeps_long_idle_timeout_until_peer_fin() {
        with_skel(|skel| {
            for first in [0, 1] {
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, GENERATION, 0));
                for _ in 0..2 {
                    let fin = run_advance(skel, PROTO_TCP, TCP_FIN, first);
                    assert_eq!((fin.action, fin.status), (0, CT_ACTIVE));
                }
                for expected in [CT_IDLE_CHECK_1, CT_IDLE_CHECK_2] {
                    assert_eq!(run_step(skel, PROTO_TCP, false).status, expected);
                }
                let idle = run_step(skel, PROTO_TCP, false);
                assert_eq!((idle.status, idle.next_timeout), (CT_WAIT_TIMEOUT, TCP_TIMEOUT));
                let peer = 1 - first;
                assert_eq!(run_advance(skel, PROTO_TCP, TCP_ACK, peer).status, CT_ACTIVE);
                let fin = run_advance(skel, PROTO_TCP, TCP_FIN, peer);
                assert_eq!((fin.action, fin.status), (0, CT_ACTIVE));
                for phase in [TCP_SYN, TCP_SYN_ACK] {
                    assert_eq!(run_advance(skel, PROTO_TCP, phase, first).action, 2);
                }
                let closing = run_step(skel, PROTO_TCP, false);
                assert_eq!(
                    (closing.status, closing.next_timeout),
                    (CT_WAIT_TCP_CLOSE, TCP_CLOSE_TIMEOUT)
                );
                for phase in [TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN] {
                    let late = run_advance(skel, PROTO_TCP, phase, peer);
                    assert_eq!(
                        (late.action, late.status),
                        (if phase == TCP_SYN { 2 } else { 0 }, CT_WAIT_TCP_CLOSE)
                    );
                }
            }
        });
    }

    #[test]
    fn rst_uses_normal_tcp_idle_timeout() {
        with_skel(|skel| {
            for direction in [0, 1] {
                for (handshake, timeout) in [(LAN_SYN, TCP_SYN_TIMEOUT), (BOTH_SYN, TCP_TIMEOUT)] {
                    let mut ct = ct_value(CT_WAIT_TIMEOUT, GENERATION, 1);
                    ct.tcp_flags = handshake;
                    put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct);
                    for _ in 0..2 {
                        let rst = run_advance(skel, PROTO_TCP, TCP_RST, direction);
                        assert_eq!((rst.action, rst.status), (0, CT_ACTIVE));
                    }
                    assert_eq!(run_step(skel, PROTO_TCP, false).status, CT_IDLE_CHECK_1);
                    assert_eq!(
                        run_advance(skel, PROTO_TCP, TCP_ACK, 1 - direction).status,
                        CT_ACTIVE
                    );
                    for expected in [CT_IDLE_CHECK_1, CT_IDLE_CHECK_2] {
                        assert_eq!(run_step(skel, PROTO_TCP, false).status, expected);
                    }
                    let idle = run_step(skel, PROTO_TCP, false);
                    assert_eq!((idle.status, idle.next_timeout), (CT_WAIT_TIMEOUT, timeout));
                }
            }
        });
    }

    #[test]
    fn unanswered_syn_then_fin_keeps_short_handshake_timeout() {
        with_skel(|skel| {
            for direction in [0, 1] {
                let mut ct = ct_value(CT_READY, GENERATION, 0);
                ct.tcp_flags = 0;
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct);
                for phase in [TCP_SYN, TCP_FIN] {
                    assert_eq!(run_advance(skel, PROTO_TCP, phase, direction).action, 0);
                }
                for expected in [CT_IDLE_CHECK_1, CT_IDLE_CHECK_2] {
                    assert_eq!(run_step(skel, PROTO_TCP, false).status, expected);
                }
                let idle = run_step(skel, PROTO_TCP, false);
                assert_eq!((idle.status, idle.next_timeout), (CT_WAIT_TIMEOUT, TCP_SYN_TIMEOUT));
            }
        });
    }

    #[test]
    fn only_initial_syn_after_rst_starts_a_fresh_handshake() {
        with_skel(|skel| {
            for (initiator, syn_flag) in [(0, WAN_SYN), (1, LAN_SYN)] {
                let peer = 1 - initiator;
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, GENERATION, 0));
                run_advance(skel, PROTO_TCP, TCP_FIN, initiator);
                let rst = run_advance(skel, PROTO_TCP, TCP_RST, peer);
                let delayed_syn_ack = run_advance(skel, PROTO_TCP, TCP_SYN_ACK, peer);
                assert_eq!((delayed_syn_ack.action, delayed_syn_ack.tcp_flags), (0, rst.tcp_flags));

                let syn = run_advance(skel, PROTO_TCP, TCP_SYN, initiator);
                assert_eq!((syn.action, syn.tcp_flags), (0, syn_flag));
                for expected in [CT_IDLE_CHECK_1, CT_IDLE_CHECK_2] {
                    assert_eq!(run_step(skel, PROTO_TCP, false).status, expected);
                }
                let idle = run_step(skel, PROTO_TCP, false);
                assert_eq!((idle.status, idle.next_timeout), (CT_WAIT_TIMEOUT, TCP_SYN_TIMEOUT));
                let reply = run_advance(skel, PROTO_TCP, TCP_SYN_ACK, peer);
                assert_eq!((reply.action, reply.tcp_flags, reply.status), (0, BOTH_SYN, CT_ACTIVE));
                run_advance(skel, PROTO_TCP, TCP_FIN, peer);
                assert_eq!(run_step(skel, PROTO_TCP, false).status, CT_IDLE_CHECK_1);
                run_advance(skel, PROTO_TCP, TCP_FIN, initiator);
                assert_eq!(run_step(skel, PROTO_TCP, false).status, CT_WAIT_TCP_CLOSE);
            }
        });
    }

    #[test]
    fn packet_only_arms_timer_when_waking_a_long_idle_wait() {
        with_skel(|skel| {
            let input =
                types::napt_ct_timer_test_input { key: ct_key(PROTO_TCP), ..Default::default() };
            skel.maps
                .napt_ct_timer_test_input
                .update(&0u32.to_ne_bytes(), as_bytes(&input), MapFlags::ANY)
                .unwrap();
            for (status, armed) in [
                (CT_READY, 0),
                (CT_ACTIVE, 0),
                (CT_IDLE_CHECK_1, 0),
                (CT_IDLE_CHECK_2, 0),
                (CT_WAIT_TIMEOUT, 1),
                (CT_WAIT_TCP_CLOSE, 0),
            ] {
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(status, GENERATION, 1));
                let data = [0; 64];
                let run = ProgramInput { data_in: Some(&data), ..Default::default() };
                let result = skel.progs.napt_ct_packet_wakeup_test.test_run(run).unwrap();
                assert_eq!(result.return_value, armed, "CT status {status}");
            }
        });
    }

    #[test]
    fn early_wakeup_preserves_idle_and_close_deadlines() {
        with_skel(|skel| {
            let read_ct = || {
                let key = ct_key(PROTO_TCP);
                let bytes =
                    skel.maps.napt_ct.lookup(as_bytes(&key), MapFlags::ANY).unwrap().unwrap();
                read_unaligned::<types::napt_ct_value>(&bytes)
            };
            for (waiting, timeout) in
                [(CT_WAIT_TIMEOUT, TCP_TIMEOUT), (CT_WAIT_TCP_CLOSE, TCP_CLOSE_TIMEOUT)]
            {
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_IDLE_CHECK_2, GENERATION, 1));
                if waiting == CT_WAIT_TCP_CLOSE {
                    run_advance(skel, PROTO_TCP, TCP_FIN, 0);
                    run_advance(skel, PROTO_TCP, TCP_FIN, 1);
                }
                let entered = run_step(skel, PROTO_TCP, false);
                assert_eq!((entered.status, entered.next_timeout), (waiting, timeout));
                let deadline = read_ct().wait_deadline_ns;
                if waiting == CT_WAIT_TCP_CLOSE {
                    run_advance(skel, PROTO_TCP, TCP_RST, 1);
                }
                let early = run_step(skel, PROTO_TCP, false);
                assert_eq!((early.action, early.status), (STEP_RESTART, waiting));
                assert!((1..timeout).contains(&early.next_timeout));

                let mut expired = read_ct();
                assert_eq!(expired.wait_deadline_ns, deadline);
                expired.wait_deadline_ns = 1;
                put_ct(&skel.maps.napt_ct, PROTO_TCP, &expired);
                let done = run_step(skel, PROTO_TCP, false);
                assert_eq!((done.action, done.timer_exists), (STEP_DELETE_CT, 0));
            }
        });
    }

    #[test]
    fn tcp_fin_across_tc_and_xdp_wakes_idle_timer_and_returns_port_after_close_wait() {
        use super::super::common::{self, WAN_IP};
        use crate::skel::xdp_nat4_v4::XdpNat4V4SkelBuilder;
        use crate::tests::helper::net::wait_for;
        use std::os::fd::AsFd;
        use std::time::{Duration, Instant};

        common::with_skel(&[], &[NAT_PORT], &[], |tc| {
            let mut object = MaybeUninit::uninit();
            let mut open = XdpNat4V4SkelBuilder::default().open(&mut object).unwrap();
            open.maps.rodata_data.as_deref_mut().unwrap().land_nat_external_addr = be32(WAN_IP);
            open.maps.napt_ct.reuse_fd(tc.maps.napt_ct.as_fd()).unwrap();
            open.maps.napt_from_lan.reuse_fd(tc.maps.napt_from_lan.as_fd()).unwrap();
            open.maps.napt_from_wan.reuse_fd(tc.maps.napt_from_wan.as_fd()).unwrap();
            let xdp = open.load().unwrap();

            let mut timer_object = MaybeUninit::uninit();
            let mut open = TestNat4V4CtTimerSkelBuilder::default().open(&mut timer_object).unwrap();
            open.maps.napt_ct.reuse_fd(tc.maps.napt_ct.as_fd()).unwrap();
            let timer = open.load().unwrap();
            let key = ct_key(PROTO_TCP);
            let input = types::napt_ct_timer_test_input { key, ..Default::default() };
            timer
                .maps
                .napt_ct_timer_test_input
                .update(&0u32.to_ne_bytes(), as_bytes(&input), MapFlags::ANY)
                .unwrap();

            let tcp = |src: Ipv4Addr, dst: Ipv4Addr, sport, dport, phase, payload: &[u8]| {
                let mut pkt = Vec::new();
                let builder = etherparse::PacketBuilder::ethernet2([2; 6], [4; 6])
                    .ipv4(src.octets(), dst.octets(), 64)
                    .tcp(sport, dport, 42, 4096)
                    .ack(1);
                let builder = match phase {
                    TCP_SYN_ACK => builder.syn(),
                    TCP_FIN => builder.fin(),
                    TCP_RST => builder.rst(),
                    TCP_ACK => builder,
                    _ => unreachable!(),
                };
                builder.write(&mut pkt, payload).unwrap();
                pkt
            };
            let from_wan = |packet: &[u8]| {
                let mut translated = vec![0; packet.len()];
                let result = xdp
                    .progs
                    .ingress_nat_v4_v4
                    .test_run(ProgramInput {
                        data_in: Some(packet),
                        data_out: Some(&mut translated),
                        ..Default::default()
                    })
                    .unwrap();
                assert_eq!(result.return_value, 2); // XDP_PASS
                assert_eq!(common::parse_tcp_ports(result.data.unwrap()), (REMOTE_PORT, LAN_PORT));
                translated
            };
            let syn = common::tcp_pkt(LAN_IP, REMOTE_IP, LAN_PORT, REMOTE_PORT, true);
            let syn_ack = tcp(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT, TCP_SYN_ACK, &[]);
            let first = tcp(LAN_IP, REMOTE_IP, LAN_PORT, REMOTE_PORT, TCP_FIN, &[]);
            assert_eq!(common::run(&tc.progs.tc_v4_from_lan, &syn).0, -1);
            from_wan(&syn_ack);
            assert_eq!(common::run(&tc.progs.tc_v4_from_lan, &first).0, -1);
            from_wan(&tcp(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT, TCP_RST, &[]));
            from_wan(&syn_ack); // Delayed reply from the old handshake.
            let (action, out) = common::run(&tc.progs.tc_v4_from_lan, &syn);
            assert_eq!(action, -1);
            assert_eq!(common::parse_tcp_ports(&out), (NAT_PORT, REMOTE_PORT));
            let bytes = tc.maps.napt_ct.lookup(as_bytes(&key), MapFlags::ANY).unwrap().unwrap();
            assert_eq!(read_unaligned::<types::napt_ct_value>(&bytes).tcp_flags, LAN_SYN);
            from_wan(&syn_ack);
            assert_eq!(common::run(&tc.progs.tc_v4_from_lan, &first).0, -1);
            let peer_data =
                tcp(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT, TCP_ACK, b"last response");
            assert!(from_wan(&peer_data).ends_with(b"last response"));
            let lookup = || {
                tc.maps
                    .napt_ct
                    .lookup(as_bytes(&key), MapFlags::ANY)
                    .unwrap()
                    .map(|bytes| read_unaligned::<types::napt_ct_value>(&bytes).status)
            };
            wait_for("half-closed CT to enter the long idle wait", Duration::from_secs(6), || {
                lookup() == Some(CT_WAIT_TIMEOUT)
            });
            let second = tcp(REMOTE_IP, WAN_IP, REMOTE_PORT, NAT_PORT, TCP_FIN, &[]);
            let before_close = Instant::now();
            from_wan(&second);
            assert_eq!(common::run(&tc.progs.tc_v4_from_lan, &syn).0, 2); // TC_ACT_SHOT
            let run = ProgramInput { data_in: Some(&second), ..Default::default() };
            assert_eq!(
                timer.progs.napt_ct_rearm_idle_timer_test.test_run(run).unwrap().return_value,
                0
            );
            wait_for("next tick to start the TCP close wait", Duration::from_secs(3), || {
                lookup() == Some(CT_WAIT_TCP_CLOSE)
            });
            let ack = common::tcp_pkt(LAN_IP, REMOTE_IP, LAN_PORT, REMOTE_PORT, false);
            let (action, out) = common::run(&tc.progs.tc_v4_from_lan, &ack);
            assert_eq!(action, -1);
            assert_eq!(common::parse_tcp_ports(&out), (NAT_PORT, REMOTE_PORT));
            assert_eq!(lookup(), Some(CT_WAIT_TCP_CLOSE));

            wait_for("TCP close timer to release the CT", Duration::from_secs(9), || {
                lookup().is_none()
            });
            assert!(before_close.elapsed() >= Duration::from_nanos(TCP_CLOSE_TIMEOUT));
            let bytes =
                tc.maps.napt_tcp_ports.lookup_and_delete(&[]).unwrap().expect("recycled port");
            let slot = read_unaligned::<types::napt_port_slot>(&bytes);
            assert_eq!((u16::from_be(slot.port), slot.generation), (NAT_PORT, 1));
            assert!(tc.maps.napt_tcp_ports.lookup_and_delete(&[]).unwrap().is_none());
        });
    }

    #[test]
    fn timeout_with_last_ref_closes_mapping_and_enters_delete_lan_mapping() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_WAIT_TIMEOUT, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_DELETE_LAN_MAPPING);
            assert_eq!(result.next_timeout, CLEAN_STEP_NS);
            assert_dynamic_mapping(skel, STATE_CLOSED, 0);
        });
    }

    #[test]
    fn last_ref_release_retries_when_another_ct_acquires_a_ref() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 2)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE_REF, GENERATION, 0));

            // The timer saw one reference before the other CT acquired the second.
            let retry = run_step_with_input(
                skel,
                types::napt_ct_timer_test_input {
                    key: ct_key(PROTO_UDP),
                    observed_state_ref: state_ref(STATE_ACTIVE, 1),
                    ..Default::default()
                },
            );
            assert_eq!((retry.action, retry.status), (STEP_RESTART, CT_RELEASE_REF));
            assert_eq!(retry.next_timeout, CLEAN_STEP_NS);
            assert_dynamic_mapping(skel, STATE_ACTIVE, 2);

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_dynamic_mapping(skel, STATE_ACTIVE, 1);
            assert!(skel.maps.napt_udp_ports.lookup_and_delete(&[]).unwrap().is_none());
        });
    }

    #[test]
    fn timeout_with_generation_mismatch_deletes_only_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION + 1));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION + 1, state_ref(STATE_ACTIVE, 1)),
            );
            for status in [CT_WAIT_TIMEOUT, CT_RELEASE_REF] {
                put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(status, GENERATION, 0));
                let result = run_step(skel, PROTO_UDP, false);
                assert_eq!(result.action, STEP_DELETE_CT);
                assert_eq!(result.timer_exists, 0);
                assert_eq!(result.lan_exists, 1);
                assert_eq!(result.wan_exists, 1);
                let wan = lookup_wan(&skel.maps.napt_from_wan, PROTO_UDP).unwrap();
                assert_eq!(wan.kind, KIND_DYNAMIC);
                assert_eq!(wan.generation, GENERATION + 1);
                assert_eq!(wan.state_ref, state_ref(STATE_ACTIVE, 1));
                assert!(skel.maps.napt_udp_ports.lookup_and_delete(&[]).unwrap().is_none());
            }
        });
    }

    #[test]
    fn timer_in_acquire_ref_deletes_only_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_ACQUIRE_REF, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_eq!(result.wan_exists, 1);
        });
    }

    #[test]
    fn static_mapping_survives_ct_timeout() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_STATIC, 0));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_STATIC, 0, state_ref(STATE_ACTIVE, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_WAIT_TIMEOUT, 0, 1));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_STATIC);
        });
    }

    #[test]
    fn delete_lan_mapping_advances_to_clear_wan_slot() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_CLOSED, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_DELETE_LAN_MAPPING, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_CLEAR_WAN_SLOT);
            assert_eq!(result.lan_exists, 0);
            assert_eq!(result.wan_exists, 1);
        });
    }

    #[test]
    fn clear_wan_slot_advances_to_return_port() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_CLOSED, 0)),
            );
            let mut ct = ct_value(CT_CLEAR_WAN_SLOT, GENERATION, 0);
            ct.cleanup_retry_ns = CLEAN_RETRY_MAX_NS as u32;
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct);

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_RETURN_PORT);
            assert_eq!(result.next_timeout, CLEAN_STEP_NS);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_FREE);
            assert_eq!(run_step(skel, PROTO_UDP, true).next_timeout, CLEAN_STEP_NS);
        });
    }

    #[test]
    fn clear_wan_slot_generation_mismatch_stops_cleanup() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION + 1));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION + 1, state_ref(STATE_CLOSED, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_CLEAR_WAN_SLOT, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_DYNAMIC);
        });
    }

    #[test]
    fn return_port_retries_and_then_deletes_ct() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RETURN_PORT, GENERATION, 0));

            let mut delay = CLEAN_STEP_NS;
            for _ in 0..20 {
                let retry = run_step(skel, PROTO_UDP, true);
                assert_eq!(retry.action, STEP_RESTART);
                assert_eq!(retry.queue_push_ret, -1);
                assert_eq!(retry.status, CT_RETURN_PORT);
                assert_eq!(retry.next_timeout, delay);
                delay = (delay * 2).min(CLEAN_RETRY_MAX_NS);
            }

            let lookup = run_resolve(skel, PROTO_UDP, GENERATION + 1, KIND_DYNAMIC);
            assert_eq!((lookup.action, lookup.timer_exists), (0, 1));

            let done = run_step(skel, PROTO_UDP, false);
            assert_eq!(done.action, STEP_DELETE_CT);
            assert_eq!(done.queue_push_ret, 0);
            assert_eq!(done.timer_exists, 0);
        });
    }

    #[test]
    fn kernel_timer_returns_port_after_full_queue_drains_with_metric_ring_full() {
        use crate::tests::helper::net::wait_for;
        use std::time::Duration;

        let mut object = MaybeUninit::uninit();
        let mut open = TestNat4V4CtTimerSkelBuilder::default().open(&mut object).unwrap();
        open.maps.napt_udp_ports.set_max_entries(2).unwrap();
        open.maps.nat_metric_events.set_max_entries(4096).unwrap();
        let skel = open.load().unwrap();
        fill_metric_ring(&skel);
        let ports = &skel.maps.napt_udp_ports;
        let occupied = [NAT_PORT + 1, NAT_PORT + 2];
        for port in occupied {
            super::super::common::queue_push(ports, port, 0);
        }
        put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
        put_wan(
            &skel.maps.napt_from_wan,
            PROTO_UDP,
            &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 1)),
        );
        put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_WAIT_TIMEOUT, GENERATION, 0));

        // Arm the production callback once. Only kernel timers advance this CT.
        let key = ct_key(PROTO_UDP);
        let input = types::napt_ct_timer_test_input { key, ..Default::default() };
        skel.maps
            .napt_ct_timer_test_input
            .update(&0u32.to_ne_bytes(), as_bytes(&input), MapFlags::ANY)
            .unwrap();
        let packet = [0u8; 64];
        let run = ProgramInput { data_in: Some(&packet), ..Default::default() };
        assert_eq!(skel.progs.napt_ct_start_timer_test.test_run(run).unwrap().return_value, 0);

        let lookup_ct = || skel.maps.napt_ct.lookup(as_bytes(&key), MapFlags::ANY).unwrap();
        let timeout = Duration::from_secs(3);
        wait_for("timer to retry the full port queue twice", timeout, || {
            let bytes = lookup_ct().expect("CT must own the port while the queue is full");
            let ct = read_unaligned::<types::napt_ct_value>(&bytes);
            ct.status == CT_RETURN_PORT && u64::from(ct.cleanup_retry_ns) >= 4 * CLEAN_STEP_NS
        });
        assert!(
            skel.maps
                .napt_from_lan
                .lookup(as_bytes(&lan_key(PROTO_UDP)), MapFlags::ANY)
                .unwrap()
                .is_none()
        );
        assert_eq!(lookup_wan(&skel.maps.napt_from_wan, PROTO_UDP).unwrap().kind, KIND_FREE);
        for port in occupied {
            let bytes = ports.lookup_and_delete(&[]).unwrap().expect("original queue entry");
            assert_eq!(u16::from_be(read_unaligned::<types::napt_port_slot>(&bytes).port), port);
        }

        wait_for("timer to finish returning the port", timeout, || lookup_ct().is_none());
        let bytes = ports.lookup_and_delete(&[]).unwrap().expect("recycled port");
        let slot = read_unaligned::<types::napt_port_slot>(&bytes);
        assert_eq!((u16::from_be(slot.port), slot.generation), (NAT_PORT, GENERATION + 1));
        assert!(ports.lookup_and_delete(&[]).unwrap().is_none());
    }

    #[test]
    fn racing_ct_releases_retry_and_return_the_shared_port_once() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 2)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE_REF, GENERATION, 0));
            let other = types::napt_ct_key {
                remote_port: (REMOTE_PORT + 1).to_be(),
                ..ct_key(PROTO_UDP)
            };
            skel.maps
                .napt_ct
                .update(
                    as_bytes(&other),
                    as_bytes(&ct_value(CT_WAIT_TIMEOUT, GENERATION, 0)),
                    MapFlags::NO_EXIST,
                )
                .unwrap();

            // Both CTs see two references. Let the other CT commit its release first.
            let observed_state_ref =
                lookup_wan(&skel.maps.napt_from_wan, PROTO_UDP).unwrap().state_ref;
            let first = run_step_with_input(
                skel,
                types::napt_ct_timer_test_input { key: other, ..Default::default() },
            );
            assert_eq!((first.action, first.timer_exists), (STEP_DELETE_CT, 0));
            assert_dynamic_mapping(skel, STATE_ACTIVE, 1);

            let retry = run_step_with_input(
                skel,
                types::napt_ct_timer_test_input {
                    key: ct_key(PROTO_UDP),
                    observed_state_ref,
                    ..Default::default()
                },
            );
            assert_eq!(
                (retry.action, retry.status, retry.timer_exists),
                (STEP_RESTART, CT_RELEASE_REF, 1)
            );
            assert_eq!(retry.next_timeout, CLEAN_STEP_NS);
            assert_eq!(retry.lan_exists, 1);
            assert_dynamic_mapping(skel, STATE_ACTIVE, 1);
            assert!(skel.maps.napt_udp_ports.lookup_and_delete(&[]).unwrap().is_none());
            assert_eq!(run_resolve(skel, PROTO_UDP, GENERATION, KIND_DYNAMIC).action, 0);
            assert_eq!(run_advance(skel, PROTO_UDP, 0, 1).status, CT_RELEASE_REF);

            let timeout = run_step(skel, PROTO_UDP, false);
            assert_eq!(timeout.status, CT_DELETE_LAN_MAPPING);
            assert_eq!(timeout.next_timeout, CLEAN_STEP_NS);
            assert_dynamic_mapping(skel, STATE_CLOSED, 0);

            let delete_lan_mapping = run_step(skel, PROTO_UDP, false);
            assert_eq!(delete_lan_mapping.status, CT_CLEAR_WAN_SLOT);
            assert_eq!(delete_lan_mapping.next_timeout, CLEAN_STEP_NS);
            assert_eq!(delete_lan_mapping.lan_exists, 0);

            let clear_wan_slot = run_step(skel, PROTO_UDP, false);
            assert_eq!(clear_wan_slot.status, CT_RETURN_PORT);
            assert_eq!(clear_wan_slot.next_timeout, CLEAN_STEP_NS);
            assert_eq!(clear_wan_slot.kind, KIND_FREE);

            let finish = run_step(skel, PROTO_UDP, false);
            assert_eq!(finish.action, STEP_DELETE_CT);
            assert_eq!(finish.queue_push_ret, 0);
            assert_eq!(finish.timer_exists, 0);
            let ports = &skel.maps.napt_udp_ports;
            let bytes = ports.lookup_and_delete(&[]).unwrap().expect("recycled port");
            let slot = read_unaligned::<types::napt_port_slot>(&bytes);
            assert_eq!((u16::from_be(slot.port), slot.generation), (NAT_PORT, GENERATION + 1));
            assert!(ports.lookup_and_delete(&[]).unwrap().is_none());
        });
    }

    #[test]
    fn advance_reactivates_wait_timeout_and_updates_client_state() {
        with_skel(|skel| {
            let mut value = ct_value(CT_WAIT_TIMEOUT, GENERATION, 0);
            value.tcp_flags = 0;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_advance(skel, PROTO_TCP, 1, 1);
            assert_eq!(result.action, 0);
            assert_eq!(result.status, CT_ACTIVE);
            assert_eq!(result.tcp_flags, LAN_SYN);
        });
    }

    #[test]
    fn advance_reactivates_wait_timeout_and_updates_server_state() {
        with_skel(|skel| {
            let mut value = ct_value(CT_WAIT_TIMEOUT, GENERATION, 0);
            value.tcp_flags = 0;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_advance(skel, PROTO_TCP, 1, 0);
            assert_eq!(result.action, 0);
            assert_eq!(result.status, CT_ACTIVE);
            assert_eq!(result.tcp_flags, WAN_SYN);
        });
    }

    #[test]
    fn resolve_rejects_previous_generation_after_wrap_to_zero() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, GENERATION, 0));

            let result = run_resolve(skel, PROTO_TCP, 0, KIND_DYNAMIC);
            assert_eq!(result.action, 0);
            assert_eq!(result.timer_exists, 0);
        });
    }

    #[test]
    fn resolve_accepts_matching_zero_generation() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, 0, 0));

            let result = run_resolve(skel, PROTO_TCP, 0, KIND_DYNAMIC);
            assert_eq!(result.action, 1);
            assert_eq!(result.timer_exists, 1);
            assert_eq!(result.r#gen, 0);
        });
    }

    #[test]
    fn resolve_static_ct_does_not_require_generation_match() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_ACTIVE, GENERATION, 1));

            let result = run_resolve(skel, PROTO_TCP, 0, KIND_STATIC);
            assert_eq!(result.action, 1);
            assert_eq!(result.timer_exists, 1);
        });
    }

    #[test]
    fn advance_does_not_reactivate_cleanup_state() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_DELETE_LAN_MAPPING, GENERATION, 0));

            for phase in [TCP_SYN, TCP_FIN, TCP_RST, TCP_ACK] {
                let result = run_advance(skel, PROTO_TCP, phase, 1);
                assert_eq!((result.action, result.status), (2, CT_DELETE_LAN_MAPPING));
                assert_eq!(result.tcp_flags, BOTH_SYN);
            }
        });
    }
}
