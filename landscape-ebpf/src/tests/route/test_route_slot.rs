use std::{mem::MaybeUninit, net::Ipv6Addr};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::tests::{
    isolated_pin_root,
    route::{
        map_helper::as_bytes,
        packet_builder::simple_ipv6_tcp_syn,
        test_route::{self, TestRouteSkelBuilder},
    },
};

fn put_rt6_target_slot(
    skel: &test_route::TestRouteSkel<'_>,
    flow_id: u32,
    slot: u32,
    ifindex: u32,
) {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Route6SlotKey {
        flow_id: u32,
        slot: u32,
    }

    let key = Route6SlotKey { flow_id, slot };

    let value = test_route::types::route6_target_info {
        ifindex,
        has_mac: 0,
        is_docker: 0,
        ..Default::default()
    };

    skel.maps
        .rt6_slot_map
        .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
        .expect("insert rt6 target slot");
}

#[test]
fn default_flow_reads_target_from_slot_map() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-slot-priority");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    put_rt6_target_slot(&skel, 0, 0, 21);

    let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
    let result = skel
        .progs
        .test_route6_pick_wan_by_flow_id_default
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run test_route6_pick_wan_by_flow_id_default");

    assert_eq!(result.return_value as i32, 21);
}

#[test]
fn non_default_flow_reads_target_from_slot_map() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-slot-non-default");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    put_rt6_target_slot(&skel, 5, 0, 21);

    let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
    let result = skel
        .progs
        .test_route6_pick_wan_by_flow_id_non_default
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run test_route6_pick_wan_by_flow_id_non_default");

    assert_eq!(result.return_value as i32, 21);
}

#[test]
fn default_flow_without_slots_passes() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-slot-default-miss");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
    let result = skel
        .progs
        .test_route6_pick_wan_by_flow_id_default
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run test_route6_pick_wan_by_flow_id_default miss");

    assert_eq!(result.return_value as i32, -1);
}

#[test]
fn non_default_flow_without_slots_drops() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-slot-non-default-miss");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
    let result = skel
        .progs
        .test_route6_pick_wan_by_flow_id_non_default
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run test_route6_pick_wan_by_flow_id_non_default miss");

    assert_eq!(result.return_value as i32, 2);
}
