use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::tests::{
    isolated_pin_root,
    route::{
        map_helper::{local_addr, remote_addr},
        packet_builder::simple_ipv6_tcp_syn,
        test_route::TestRouteSkelBuilder,
    },
};

#[test]
fn cached_docker_target_recovers_flow_vlan_id_from_mark() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-cached-docker-vlan");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());

    let result = skel
        .progs
        .test_route_cached_docker_vlan_id
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run cached docker vlan redirect");

    assert_eq!(result.return_value, 0xc05);
}

#[test]
fn cached_docker_vlan_push_uses_flow_vlan_id_from_mark() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-cached-docker-vlan-push");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());

    let result = skel
        .progs
        .test_route_cached_docker_redirect_v6
        .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
        .expect("run cached docker vlan push");

    assert_eq!(result.return_value, 0x0c05);
}
