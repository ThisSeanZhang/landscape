use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

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

const CT_PENDING_REF: u64 = 10;
const CT_ACTIVE: u64 = 20;
const CT_IDLE_1: u64 = 30;
const CT_IDLE_2: u64 = 31;
const CT_RELEASE: u64 = 40;
const CT_DELETE_EGRESS: u64 = 50;
const CT_DELETE_INGRESS: u64 = 51;
const CT_PUSH_QUEUE: u64 = 52;

const STEP_DELETE_CT: u32 = 1;
const STEP_RESTART: u32 = 2;

const REPORT_INTERVAL: u64 = 5_000_000_000;
const TCP_SYN_TIMEOUT: u64 = 6_000_000_000;
const TCP_TIMEOUT: u64 = 600_000_000_000;
const UDP_TIMEOUT: u64 = 300_000_000_000;
const DELETE_RETRY_INTERVAL: u64 = 100_000_000;
const QUEUE_RETRY_INTERVAL: u64 = 500_000_000;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
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
        client_status: 1,
        server_status: 1,
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

fn push_queue<M: MapCore>(map: &M, port: u16, generation: u32) {
    let mut slot = [0u8; 8];
    slot[0..2].copy_from_slice(&port.to_be_bytes());
    slot[4..8].copy_from_slice(&generation.to_ne_bytes());
    let ret = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map.as_fd().as_raw_fd(),
            std::ptr::null(),
            slot.as_ptr().cast(),
            0,
        )
    };
    assert_eq!(ret, 0, "queue push failed");
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
    let input = types::napt_ct_timer_test_input {
        key: ct_key(proto),
        force_queue_push_fail: force_queue_push_fail as u8,
        pad: [0; 3],
    };
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

fn lookup_wan<M: MapCore>(map: &M, proto: u8) -> Option<types::napt_from_wan_value> {
    let key = wan_index(proto, NAT_PORT).to_ne_bytes();
    map.lookup(&key, MapFlags::ANY).unwrap().map(|bytes| read_unaligned(&bytes))
}

fn lookup_lan<M: MapCore>(map: &M, proto: u8) -> Option<types::napt_from_lan_value> {
    let key = lan_key(proto);
    map.lookup(as_bytes(&key), MapFlags::ANY).unwrap().map(|bytes| read_unaligned(&bytes))
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

    #[test]
    fn active_transitions_to_idle_1() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_ACTIVE, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_IDLE_1);
            assert_eq!(result.next_timeout, REPORT_INTERVAL);
        });
    }

    #[test]
    fn idle_1_transitions_to_idle_2() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_IDLE_1, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_IDLE_2);
            assert_eq!(result.next_timeout, REPORT_INTERVAL);
        });
    }

    #[test]
    fn idle_2_transitions_to_release_with_udp_timeout() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_IDLE_2, GENERATION, 0));
            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_RELEASE);
            assert_eq!(result.next_timeout, UDP_TIMEOUT);
        });
    }

    #[test]
    fn idle_2_tcp_syn_uses_tcp_timeout() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &ct_value(CT_IDLE_2, GENERATION, 0));
            let result = run_step(skel, PROTO_TCP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_RELEASE);
            assert_eq!(result.next_timeout, TCP_TIMEOUT);
        });
    }

    #[test]
    fn idle_2_tcp_non_syn_uses_syn_timeout() {
        with_skel(|skel| {
            let mut value = ct_value(CT_IDLE_2, GENERATION, 0);
            value.client_status = 3;
            value.server_status = 3;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_step(skel, PROTO_TCP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_RELEASE);
            assert_eq!(result.next_timeout, TCP_SYN_TIMEOUT);
        });
    }

    #[test]
    fn release_last_ref_closes_mapping_and_enters_delete_egress() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_DELETE_EGRESS);
            assert_eq!(result.next_timeout, DELETE_RETRY_INTERVAL);
            assert_dynamic_mapping(skel, STATE_CLOSED, 1);
        });
    }

    #[test]
    fn release_multiple_refs_decrements_and_deletes_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 2)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_dynamic_mapping(skel, STATE_ACTIVE, 1);
        });
    }

    #[test]
    fn release_generation_mismatch_deletes_only_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION + 1));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION + 1, state_ref(STATE_ACTIVE, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_eq!(result.wan_exists, 1);
            let wan = lookup_wan(&skel.maps.napt_from_wan, PROTO_UDP).unwrap();
            assert_eq!(wan.kind, KIND_DYNAMIC);
            assert_eq!(wan.generation, GENERATION + 1);
            assert_eq!(wan.state_ref, state_ref(STATE_ACTIVE, 1));
        });
    }

    #[test]
    fn pending_ref_deletes_only_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_PENDING_REF, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_eq!(result.wan_exists, 1);
        });
    }

    #[test]
    fn static_release_keeps_mapping_and_deletes_ct() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_STATIC, 0));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_STATIC, 0, state_ref(STATE_ACTIVE, 0)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE, 0, 1));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.lan_exists, 1);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_STATIC);
        });
    }

    #[test]
    fn delete_egress_removes_lan_and_enters_delete_ingress() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_CLOSED, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_DELETE_EGRESS, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_DELETE_INGRESS);
            assert_eq!(result.lan_exists, 0);
            assert_eq!(result.wan_exists, 1);
        });
    }

    #[test]
    fn delete_ingress_clears_array_and_enters_push_queue() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_CLOSED, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_DELETE_INGRESS, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_RESTART);
            assert_eq!(result.status, CT_PUSH_QUEUE);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_FREE);
        });
    }

    #[test]
    fn delete_ingress_generation_mismatch_stops_cleanup() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION + 1));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION + 1, state_ref(STATE_CLOSED, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_DELETE_INGRESS, GENERATION, 0));

            let result = run_step(skel, PROTO_UDP, false);
            assert_eq!(result.action, STEP_DELETE_CT);
            assert_eq!(result.timer_exists, 0);
            assert_eq!(result.wan_exists, 1);
            assert_eq!(result.kind, KIND_DYNAMIC);
        });
    }

    #[test]
    fn push_queue_retries_and_then_deletes_ct() {
        with_skel(|skel| {
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_PUSH_QUEUE, GENERATION, 0));

            let retry = run_step(skel, PROTO_UDP, true);
            assert_eq!(retry.action, STEP_RESTART);
            assert_eq!(retry.queue_push_ret, -1);
            assert_eq!(retry.status, CT_PUSH_QUEUE);
            assert_eq!(retry.next_timeout, QUEUE_RETRY_INTERVAL);

            let done = run_step(skel, PROTO_UDP, false);
            assert_eq!(done.action, STEP_DELETE_CT);
            assert_eq!(done.queue_push_ret, 0);
            assert_eq!(done.timer_exists, 0);
        });
    }

    #[test]
    fn full_release_cleanup_sequence_completes() {
        with_skel(|skel| {
            put_lan(&skel.maps.napt_from_lan, PROTO_UDP, &lan_value(KIND_DYNAMIC, GENERATION));
            put_wan(
                &skel.maps.napt_from_wan,
                PROTO_UDP,
                &wan_value(KIND_DYNAMIC, GENERATION, state_ref(STATE_ACTIVE, 1)),
            );
            put_ct(&skel.maps.napt_ct, PROTO_UDP, &ct_value(CT_RELEASE, GENERATION, 0));

            let release = run_step(skel, PROTO_UDP, false);
            assert_eq!(release.status, CT_DELETE_EGRESS);

            let delete_egress = run_step(skel, PROTO_UDP, false);
            assert_eq!(delete_egress.status, CT_DELETE_INGRESS);
            assert_eq!(delete_egress.lan_exists, 0);

            let delete_ingress = run_step(skel, PROTO_UDP, false);
            assert_eq!(delete_ingress.status, CT_PUSH_QUEUE);
            assert_eq!(delete_ingress.kind, KIND_FREE);

            let finish = run_step(skel, PROTO_UDP, false);
            assert_eq!(finish.action, STEP_DELETE_CT);
            assert_eq!(finish.queue_push_ret, 0);
            assert_eq!(finish.timer_exists, 0);
        });
    }

    #[test]
    fn advance_reactivates_release_and_updates_client_state() {
        with_skel(|skel| {
            let mut value = ct_value(CT_RELEASE, GENERATION, 0);
            value.client_status = 0;
            value.server_status = 0;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_advance(skel, PROTO_TCP, 1, 1);
            assert_eq!(result.action, 0);
            assert_eq!(result.status, CT_ACTIVE);
            assert_eq!(result.client_status, 1);
            assert_eq!(result.server_status, 0);
        });
    }

    #[test]
    fn advance_reactivates_release_and_updates_server_state() {
        with_skel(|skel| {
            let mut value = ct_value(CT_RELEASE, GENERATION, 0);
            value.client_status = 0;
            value.server_status = 0;
            put_ct(&skel.maps.napt_ct, PROTO_TCP, &value);
            let result = run_advance(skel, PROTO_TCP, 1, 0);
            assert_eq!(result.action, 0);
            assert_eq!(result.status, CT_ACTIVE);
            assert_eq!(result.client_status, 0);
            assert_eq!(result.server_status, 1);
        });
    }
}
