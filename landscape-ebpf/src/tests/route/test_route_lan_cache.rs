use std::{mem::MaybeUninit, net::Ipv4Addr};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::tests::{
    helper::map::{
        LAN_CACHE, as_bytes, create_route4_cache_inner_map, create_route6_cache_inner_map,
        local_addr, lookup_rt4_cache_value, lookup_rt6_cache_value, remote_addr,
    },
    isolated_pin_root,
    pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn},
    route::test_route::{TestRouteSkel, TestRouteSkelBuilder, types},
};

fn with_route_skel(name: &str, test: impl FnOnce(&TestRouteSkel<'_>)) {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root(name);
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut object = MaybeUninit::uninit();
    let skel = builder.open(&mut object).unwrap().load().unwrap();
    test(&skel);
}

// Call the writer directly: a missing slot on first-packet lookup would never reach it.
fn run_cache_writer(prog: &ProgramMut<'_>, packet: &[u8]) {
    let result =
        prog.test_run(ProgramInput { data_in: Some(packet), ..Default::default() }).unwrap();
    assert_eq!(result.return_value, 0, "skipping a cache insert must return TC_ACT_OK");
}

#[test]
fn v4_set_cache_in_lan_skips_unresolved_slot() {
    with_route_skel("route-helper-v4-unresolved-slot", |skel| {
        let local = Ipv4Addr::new(192, 168, 1, 10);
        let remote = Ipv4Addr::new(10, 0, 0, 20);
        let packet = simple_ipv4_tcp(local, remote);
        let map = &skel.maps.rt4_cache_map;
        create_route4_cache_inner_map(map, LAN_CACHE);
        let check_no_entry = || {
            run_cache_writer(&skel.progs.test_route4_set_cache_in_lan, &packet);
            assert!(lookup_rt4_cache_value(map, LAN_CACHE, local, remote).is_none());
        };
        check_no_entry(); // Slot disappeared before the cache write.
        for slot in 0..16 {
            let key = types::route4_slot_key { flow_id: 0, slot };
            let target = types::route4_target_info::default(); // ifindex == 0
            skel.maps
                .rt4_slot_map
                .update(as_bytes(&key), as_bytes(&target), MapFlags::ANY)
                .unwrap();
        }
        check_no_entry();
    });
}

#[test]
fn v6_set_cache_in_lan_skips_unresolved_slot() {
    with_route_skel("route-helper-v6-unresolved-slot", |skel| {
        let (local, remote) = (local_addr(), remote_addr());
        let packet = simple_ipv6_tcp_syn(local, remote);
        let map = &skel.maps.rt6_cache_map;
        create_route6_cache_inner_map(map, LAN_CACHE);
        let check_no_entry = || {
            run_cache_writer(&skel.progs.test_route6_set_cache_in_lan, &packet);
            assert!(lookup_rt6_cache_value(map, LAN_CACHE, local, remote).is_none());
        };
        check_no_entry();
        for slot in 0..16 {
            let key = types::route6_slot_key { flow_id: 0, slot };
            let target = types::route6_target_info::default();
            skel.maps
                .rt6_slot_map
                .update(as_bytes(&key), as_bytes(&target), MapFlags::ANY)
                .unwrap();
        }
        check_no_entry();
    });
}
