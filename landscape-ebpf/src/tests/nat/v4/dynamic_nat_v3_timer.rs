use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

pub(crate) mod test_nat_v3_timer {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_nat_v3_timer.skel.rs"));
}

use test_nat_v3_timer::{types, TestNatV3TimerSkelBuilder};

const NAT_MAPPING_INGRESS: u8 = 0;
const NAT_MAPPING_EGRESS: u8 = 1;
const STATE_SHIFT: u64 = 56;
const STATE_ACTIVE: u64 = 1;
const STATE_CLOSED: u64 = 2;
const CT_INIT: u64 = 0;
const CT_SYN: u64 = 1;
const CT_LESS_EST: u64 = 3;
const TIMER_PENDING_REF: u64 = 10;
const TIMER_ACTIVE: u64 = 20;
const TIMER_TIMEOUT_1: u64 = 30;
const TIMER_TIMEOUT_2: u64 = 31;
const TIMER_RELEASE: u64 = 40;
const TIMER_DELETE_EGRESS: u64 = 50;
const TIMER_DELETE_INGRESS: u64 = 51;
const TIMER_PUSH_QUEUE: u64 = 52;
const REPORT_INTERVAL: u64 = 5_000_000_000;
const TCP_SYN_TIMEOUT: u64 = 6_000_000_000;
const TCP_TIMEOUT: u64 = 600_000_000_000;
const UDP_TIMEOUT: u64 = 300_000_000_000;
const DELETE_RETRY_INTERVAL: u64 = 100_000_000;
const QUEUE_RETRY_INTERVAL: u64 = 500_000_000;
const STEP_DELETE_CT: u32 = 1;
const STEP_RESTART: u32 = 2;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(50, 18, 88, 205);
const IFINDEX: u32 = 6;
const LAN_PORT: u16 = 56186;
const NAT_PORT: u16 = 40000;
const ALT_NAT_PORT: u16 = 40001;
const GENERATION: u16 = 7;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn read_unaligned<T: Copy>(bytes: &[u8]) -> T {
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) }
}

fn state_ref(state: u64, refs: u64) -> u64 {
    (state << STATE_SHIFT) | refs
}

fn timer_key() -> types::nat4_timer_key {
    timer_key_with_proto(IPPROTO_TCP)
}

fn timer_key_with_proto(l4proto: u8) -> types::nat4_timer_key {
    types::nat4_timer_key {
        l4proto,
        _pad: [0; 3],
        pair_ip: types::inet4_pair {
            src_addr: types::inet4_addr { addr: REMOTE_IP.to_bits().to_be() },
            dst_addr: types::inet4_addr { addr: WAN_IP.to_bits().to_be() },
            src_port: 443u16.to_be(),
            dst_port: NAT_PORT.to_be(),
        },
    }
}

fn ingress_key() -> types::nat4_mapping_key {
    types::nat4_mapping_key {
        gress: NAT_MAPPING_INGRESS,
        l4proto: 6,
        from_port: NAT_PORT.to_be(),
        from_addr: WAN_IP.to_bits().to_be(),
    }
}

fn egress_key() -> types::nat4_mapping_key {
    types::nat4_mapping_key {
        gress: NAT_MAPPING_EGRESS,
        l4proto: 6,
        from_port: LAN_PORT.to_be(),
        from_addr: LAN_HOST.to_bits().to_be(),
    }
}

fn mapping_pair() -> (types::nat4_egress_mapping_value_v3, types::nat4_mapping_value_v3) {
    let mut egress = types::nat4_egress_mapping_value_v3::default();
    egress.addr = WAN_IP.to_bits().to_be();
    egress.trigger_addr = REMOTE_IP.to_bits().to_be();
    egress.port = NAT_PORT.to_be();
    egress.trigger_port = 443u16.to_be();
    egress.is_allow_reuse = 1;
    let ingress = types::nat4_mapping_value_v3 {
        state_ref: state_ref(STATE_ACTIVE, 1),
        addr: LAN_HOST.to_bits().to_be(),
        trigger_addr: REMOTE_IP.to_bits().to_be(),
        port: LAN_PORT.to_be(),
        trigger_port: 443u16.to_be(),
        generation: GENERATION,
        _pad: 0,
        is_allow_reuse: 1,
    };
    (egress, ingress)
}

fn lookup_ingress_mapping<T: MapCore>(
    map: &T,
    key: &types::nat4_mapping_key,
) -> Option<types::nat4_mapping_value_v3> {
    map.lookup(as_bytes(key), MapFlags::ANY)
        .unwrap()
        .map(|bytes| read_unaligned::<types::nat4_mapping_value_v3>(&bytes))
}

fn lookup_egress_mapping<T: MapCore>(
    map: &T,
    key: &types::nat4_mapping_key,
) -> Option<types::nat4_egress_mapping_value_v3> {
    map.lookup(as_bytes(key), MapFlags::ANY)
        .unwrap()
        .map(|bytes| read_unaligned::<types::nat4_egress_mapping_value_v3>(&bytes))
}

fn put_mapping_pair<M1: MapCore, M2: MapCore>(ingress_map: &M1, egress_map: &M2) {
    let (egress, ingress) = mapping_pair();
    egress_map.update(as_bytes(&egress_key()), as_bytes(&egress), MapFlags::ANY).unwrap();
    ingress_map.update(as_bytes(&ingress_key()), as_bytes(&ingress), MapFlags::ANY).unwrap();
}

fn put_state<T: MapCore>(map: &T, generation: u16, state_ref_: u64) {
    let key = ingress_key();
    let mut value = lookup_ingress_mapping(map, &key).expect("missing ingress mapping");
    value.generation = generation;
    value.state_ref = state_ref_;
    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).unwrap();
}

fn set_egress_target<T: MapCore>(map: &T, nat_port: u16) {
    let key = egress_key();
    let mut value = lookup_egress_mapping(map, &key).expect("missing egress mapping");
    value.addr = WAN_IP.to_bits().to_be();
    value.port = nat_port.to_be();
    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).unwrap();
}

fn delete_mapping<T: MapCore>(map: &T, key: &types::nat4_mapping_key) {
    let _ = map.delete(as_bytes(key));
}

fn put_timer<T: MapCore>(map: &T, status: u64, generation_snapshot: u16) {
    put_timer_with_key(map, &timer_key(), status, generation_snapshot, CT_SYN, CT_SYN);
}

fn put_timer_with_key<T: MapCore>(
    map: &T,
    key: &types::nat4_timer_key,
    status: u64,
    generation_snapshot: u16,
    client_status: u64,
    server_status: u64,
) {
    let mut value = types::nat4_timer_value_v3::default();
    value.server_status = server_status;
    value.client_status = client_status;
    value.status = status;
    value.client_addr = types::inet4_addr { addr: LAN_HOST.to_bits().to_be() };
    value.client_port = LAN_PORT.to_be();
    value.gress = NAT_MAPPING_EGRESS;
    value.create_time = 1;
    value.ifindex = IFINDEX;
    value.generation_snapshot = generation_snapshot;
    map.update(as_bytes(key), as_bytes(&value), MapFlags::ANY).unwrap();
}

fn put_test_input_with_key<T: MapCore>(
    map: &T,
    key: &types::nat4_timer_key,
    force_queue_push_fail: bool,
) {
    let value = types::nat4_timer_test_input_v3 {
        key: *key,
        force_queue_push_fail: force_queue_push_fail as u8,
        _pad: [0; 3],
    };
    let key = 0u32;
    map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).unwrap();
}

fn get_test_result<T: MapCore>(map: &T) -> types::nat4_timer_test_result_v3 {
    let key = 0u32;
    let bytes = map.lookup(as_bytes(&key), MapFlags::ANY).unwrap().expect("missing test result");
    read_unaligned::<types::nat4_timer_test_result_v3>(&bytes)
}

fn run_step(
    skel: &test_nat_v3_timer::TestNatV3TimerSkel<'_>,
    force_queue_push_fail: bool,
) -> types::nat4_timer_test_result_v3 {
    run_step_with_key(skel, &timer_key(), force_queue_push_fail)
}

fn run_step_with_key(
    skel: &test_nat_v3_timer::TestNatV3TimerSkel<'_>,
    key: &types::nat4_timer_key,
    force_queue_push_fail: bool,
) -> types::nat4_timer_test_result_v3 {
    put_test_input_with_key(&skel.maps.nat4_timer_test_input_v3, key, force_queue_push_fail);
    let mut data = vec![0u8; 64];
    let input = ProgramInput { data_in: Some(&mut data), ..Default::default() };
    let result = skel.progs.nat_v4_timer_step_test.test_run(input).expect("test_run failed");
    assert_eq!(result.return_value as i32, 0);
    get_test_result(&skel.maps.nat4_timer_test_result_v3)
}

fn run_advance(
    skel: &test_nat_v3_timer::TestNatV3TimerSkel<'_>,
) -> types::nat4_timer_test_result_v3 {
    put_test_input_with_key(&skel.maps.nat4_timer_test_input_v3, &timer_key(), false);
    let mut data = vec![0u8; 64];
    let input = ProgramInput { data_in: Some(&mut data), ..Default::default() };
    let result = skel.progs.nat_v4_timer_advance_test.test_run(input).expect("test_run failed");
    assert_eq!(result.return_value as i32, 0);
    get_test_result(&skel.maps.nat4_timer_test_result_v3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::nat::NAT_V3_TEST_LOCK;

    #[test]
    fn advance_reactivates_release_with_single_cas() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer(&skel.maps.nat4_timer_map, TIMER_RELEASE, GENERATION);

        let result = run_advance(&skel);

        assert_eq!(result.action as i32, 0);
        assert_eq!(u64::from(result.status), TIMER_ACTIVE);
    }

    #[test]
    fn advance_does_not_reactivate_cleanup_state() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer(&skel.maps.nat4_timer_map, TIMER_DELETE_EGRESS, GENERATION);

        let result = run_advance(&skel);

        assert_eq!(result.action as i32, 0, "cleanup state must not fail the current packet");
        assert_eq!(u64::from(result.status), TIMER_DELETE_EGRESS);
    }

    #[test]
    fn release_generation_mismatch_deletes_only_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION + 1, state_ref(STATE_ACTIVE, 1));
        put_timer(&skel.maps.nat4_timer_map, TIMER_RELEASE, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_DELETE_CT);
        assert_eq!(result.timer_exists, 0);
        assert_eq!(result.ingress_mapping_exists, 1);
        assert_eq!(result.egress_mapping_exists, 1);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.generation, GENERATION + 1);
        assert_eq!(result.state_ref, state_ref(STATE_ACTIVE, 1));
    }

    #[test]
    fn release_active_two_decrements_ref() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_ACTIVE, 2));
        put_timer(&skel.maps.nat4_timer_map, TIMER_RELEASE, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_DELETE_CT);
        assert_eq!(result.timer_exists, 0);
        assert_eq!(result.ingress_mapping_exists, 1);
        assert_eq!(result.egress_mapping_exists, 1);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.state_ref, state_ref(STATE_ACTIVE, 1));
    }

    #[test]
    fn timeout2_bi_syn_transitions_to_release_with_tcp_timeout() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_ACTIVE, 1));
        put_timer(&skel.maps.nat4_timer_map, TIMER_TIMEOUT_2, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_RELEASE);
        assert_eq!(result.next_timeout, TCP_TIMEOUT);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.state_ref, state_ref(STATE_ACTIVE, 1));
    }

    #[test]
    fn active_transitions_to_timeout1_with_report_interval() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer(&skel.maps.nat4_timer_map, TIMER_ACTIVE, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_TIMEOUT_1);
        assert_eq!(result.next_timeout, REPORT_INTERVAL);
    }

    #[test]
    fn timeout1_transitions_to_timeout2_with_report_interval() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer(&skel.maps.nat4_timer_map, TIMER_TIMEOUT_1, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_TIMEOUT_2);
        assert_eq!(result.next_timeout, REPORT_INTERVAL);
    }

    #[test]
    fn timeout2_tcp_non_syn_uses_tcp_syn_timeout() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer_with_key(
            &skel.maps.nat4_timer_map,
            &timer_key(),
            TIMER_TIMEOUT_2,
            GENERATION,
            CT_LESS_EST,
            CT_LESS_EST,
        );

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_RELEASE);
        assert_eq!(result.next_timeout, TCP_SYN_TIMEOUT);
    }

    #[test]
    fn timeout2_udp_uses_udp_timeout() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        let udp_key = timer_key_with_proto(IPPROTO_UDP);
        put_timer_with_key(
            &skel.maps.nat4_timer_map,
            &udp_key,
            TIMER_TIMEOUT_2,
            GENERATION,
            CT_INIT,
            CT_INIT,
        );

        let result = run_step_with_key(&skel, &udp_key, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_RELEASE);
        assert_eq!(result.next_timeout, UDP_TIMEOUT);
    }

    #[test]
    fn release_last_ref_transitions_to_delete_egress() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_ACTIVE, 1));
        put_timer(&skel.maps.nat4_timer_map, TIMER_RELEASE, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_DELETE_EGRESS);
        assert_eq!(result.next_timeout, DELETE_RETRY_INTERVAL);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.state_ref, state_ref(STATE_CLOSED, 1));
    }

    #[test]
    fn delete_egress_removes_old_key_and_transitions_to_delete_ingress() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_CLOSED, 1));
        put_timer(&skel.maps.nat4_timer_map, TIMER_DELETE_EGRESS, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_DELETE_INGRESS);
        assert_eq!(result.next_timeout, DELETE_RETRY_INTERVAL);
        assert_eq!(result.egress_mapping_exists, 0);
        assert_eq!(result.ingress_mapping_exists, 1);
        assert_eq!(result.state_ref, state_ref(STATE_CLOSED, 1));
    }

    #[test]
    fn delete_egress_preserves_retargeted_mapping() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_CLOSED, 1));
        set_egress_target(&skel.maps.nat4_egress_dyn_map, ALT_NAT_PORT);
        put_timer(&skel.maps.nat4_timer_map, TIMER_DELETE_EGRESS, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_DELETE_INGRESS);
        assert_eq!(result.next_timeout, DELETE_RETRY_INTERVAL);
        assert_eq!(result.egress_mapping_exists, 1);
        let egress = lookup_egress_mapping(&skel.maps.nat4_egress_dyn_map, &egress_key())
            .expect("egress mapping");
        assert_eq!(u16::from_be(egress.port), ALT_NAT_PORT);
    }

    #[test]
    fn delete_ingress_removes_same_generation_and_transitions_to_push_queue() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_CLOSED, 1));
        delete_mapping(&skel.maps.nat4_egress_dyn_map, &egress_key());
        put_timer(&skel.maps.nat4_timer_map, TIMER_DELETE_INGRESS, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_RESTART);
        assert_eq!(result.timer_exists, 1);
        assert_eq!(u64::from(result.status), TIMER_PUSH_QUEUE);
        assert_eq!(result.next_timeout, QUEUE_RETRY_INTERVAL);
        assert_eq!(result.ingress_mapping_exists, 0);
        assert_eq!(result.egress_mapping_exists, 0);
        assert_eq!(result.state_exists, 0);
    }

    #[test]
    fn delete_ingress_generation_mismatch_stops_cleanup() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION + 1, state_ref(STATE_CLOSED, 1));
        delete_mapping(&skel.maps.nat4_egress_dyn_map, &egress_key());
        put_timer(&skel.maps.nat4_timer_map, TIMER_DELETE_INGRESS, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_DELETE_CT);
        assert_eq!(result.timer_exists, 0);
        assert_eq!(result.ingress_mapping_exists, 1);
        assert_eq!(result.egress_mapping_exists, 0);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.generation, GENERATION + 1);
    }

    #[test]
    fn push_queue_retries_and_then_deletes_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_timer(&skel.maps.nat4_timer_map, TIMER_PUSH_QUEUE, GENERATION);

        let retry = run_step(&skel, true);

        assert_eq!(retry.action, STEP_RESTART);
        assert_eq!(retry.queue_push_ret, -1);
        assert_eq!(retry.timer_exists, 1);
        assert_eq!(u64::from(retry.status), TIMER_PUSH_QUEUE);
        assert_eq!(retry.next_timeout, QUEUE_RETRY_INTERVAL);

        let done = run_step(&skel, false);

        assert_eq!(done.action, STEP_DELETE_CT);
        assert_eq!(done.queue_push_ret, 0);
        assert_eq!(done.timer_exists, 0);
    }

    #[test]
    fn full_release_cleanup_sequence_completes() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_ACTIVE, 1));
        put_timer(&skel.maps.nat4_timer_map, TIMER_RELEASE, GENERATION);

        let release = run_step(&skel, false);
        assert_eq!(u64::from(release.status), TIMER_DELETE_EGRESS);

        let delete_egress = run_step(&skel, false);
        assert_eq!(u64::from(delete_egress.status), TIMER_DELETE_INGRESS);
        assert_eq!(delete_egress.egress_mapping_exists, 0);

        let delete_ingress = run_step(&skel, false);
        assert_eq!(u64::from(delete_ingress.status), TIMER_PUSH_QUEUE);
        assert_eq!(delete_ingress.ingress_mapping_exists, 0);

        let finish = run_step(&skel, false);
        assert_eq!(finish.action, STEP_DELETE_CT);
        assert_eq!(finish.queue_push_ret, 0);
        assert_eq!(finish.timer_exists, 0);
    }

    #[test]
    fn pending_ref_timer_cleanup_deletes_ct_only() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();
        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);
        put_state(&skel.maps.nat4_ingress_dyn_map, GENERATION, state_ref(STATE_ACTIVE, 0));
        put_timer(&skel.maps.nat4_timer_map, TIMER_PENDING_REF, GENERATION);

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_DELETE_CT);
        assert_eq!(result.timer_exists, 0);
        assert_eq!(result.ingress_mapping_exists, 1);
        assert_eq!(result.egress_mapping_exists, 1);
        assert_eq!(result.state_exists, 1);
        assert_eq!(result.state_ref, state_ref(STATE_ACTIVE, 0));
    }

    #[test]
    fn static_ct_release_skips_dynamic_cleanup() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TestNatV3TimerSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3-timer");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        put_mapping_pair(&skel.maps.nat4_ingress_dyn_map, &skel.maps.nat4_egress_dyn_map);

        let key = timer_key();
        let mut value = types::nat4_timer_value_v3::default();
        value.server_status = CT_SYN;
        value.client_status = CT_SYN;
        value.status = TIMER_RELEASE;
        value.client_addr = types::inet4_addr { addr: LAN_HOST.to_bits().to_be() };
        value.client_port = LAN_PORT.to_be();
        value.gress = NAT_MAPPING_INGRESS;
        value.create_time = 1;
        value.ifindex = IFINDEX;
        value.generation_snapshot = GENERATION;
        value.is_static = 1;
        skel.maps.nat4_timer_map.update(as_bytes(&key), as_bytes(&value), MapFlags::ANY).unwrap();

        let result = run_step(&skel, false);

        assert_eq!(result.action, STEP_DELETE_CT, "static CT should be deleted");
        assert_eq!(result.timer_exists, 0, "CT should no longer exist");
        assert_eq!(
            result.ingress_mapping_exists, 1,
            "dynamic ingress mapping preserved (fast path skips dynamic cleanup)"
        );
        assert_eq!(
            result.egress_mapping_exists, 1,
            "dynamic egress mapping preserved (fast path skips dynamic cleanup)"
        );
    }
}
