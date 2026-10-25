use std::os::fd::AsFd;

use libbpf_rs::{
    MapCore, MapHandle, MapInfo,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
use crate::skel::tc_nat4_v4::TcNat4V4SkelBuilder;
use crate::skel::tc_nat6::TcNat6SkelBuilder;
use crate::skel::tc_wan_ingress_root::TcWanIngressRootSkelBuilder;
use crate::skel::xdp_nat4_v4::XdpNat4V4SkelBuilder;
use crate::skel::xdp_nat6::XdpNat6SkelBuilder;

use crate::tests::{init_shared_maps_for_test, isolated_pin_root};

fn map_id<M: MapCore>(map: &M) -> u32 {
    MapInfo::new(map.as_fd()).expect("map info").info.id
}

#[test]
fn frag_caches_are_shared_by_root_and_nat_datapaths() {
    let pin_root = isolated_pin_root("frag-cache-share");
    let paths = crate::LandscapeMapPath::from_root(&pin_root);
    let _shared = init_shared_maps_for_test(&pin_root);

    let (_root_backing, root_obj) = OwnedOpenObject::new();
    let mut root_open =
        TcWanIngressRootSkelBuilder::default().open(root_obj).expect("open tc_wan_ingress_root");
    root_open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;
    root_open.maps.rodata_data.as_deref_mut().unwrap().current_chain = 1;
    pin_and_reuse_map(&mut root_open.maps.frag4_cache_lan, &paths.frag4_cache_lan).unwrap();
    pin_and_reuse_map(&mut root_open.maps.frag4_cache_wan, &paths.frag4_cache_wan).unwrap();
    pin_and_reuse_map(&mut root_open.maps.frag6_cache_lan, &paths.frag6_cache_lan).unwrap();
    pin_and_reuse_map(&mut root_open.maps.frag6_cache_wan, &paths.frag6_cache_wan).unwrap();
    let root = root_open.load().expect("load tc_wan_ingress_root");

    let (_tc4_backing, tc4_obj) = OwnedOpenObject::new();
    let mut tc4_open = TcNat4V4SkelBuilder::default().open(tc4_obj).expect("open tc_nat4_v4");
    tc4_open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;
    pin_and_reuse_map(&mut tc4_open.maps.frag4_cache_lan, &paths.frag4_cache_lan).unwrap();
    pin_and_reuse_map(&mut tc4_open.maps.frag4_cache_wan, &paths.frag4_cache_wan).unwrap();
    let tc4 = tc4_open.load().expect("load tc_nat4_v4");

    let (_xdp4_backing, xdp4_obj) = OwnedOpenObject::new();
    let mut xdp4_open = XdpNat4V4SkelBuilder::default().open(xdp4_obj).expect("open xdp_nat4_v4");
    xdp4_open
        .maps
        .frag4_cache_lan
        .reuse_fd(tc4.maps.frag4_cache_lan.as_fd())
        .expect("xdp_nat4_v4 reuse frag4_cache_lan");
    xdp4_open
        .maps
        .frag4_cache_wan
        .reuse_fd(tc4.maps.frag4_cache_wan.as_fd())
        .expect("xdp_nat4_v4 reuse frag4_cache_wan");
    let xdp4 = xdp4_open.load().expect("load xdp_nat4_v4");

    let (_tc6_backing, tc6_obj) = OwnedOpenObject::new();
    let mut tc6_open = TcNat6SkelBuilder::default().open(tc6_obj).expect("open tc_nat6");
    tc6_open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = 14;
    pin_and_reuse_map(&mut tc6_open.maps.frag6_cache_lan, &paths.frag6_cache_lan).unwrap();
    pin_and_reuse_map(&mut tc6_open.maps.frag6_cache_wan, &paths.frag6_cache_wan).unwrap();
    let tc6 = tc6_open.load().expect("load tc_nat6");

    let (_xdp6_backing, xdp6_obj) = OwnedOpenObject::new();
    let mut xdp6_open = XdpNat6SkelBuilder::default().open(xdp6_obj).expect("open xdp_nat6");
    xdp6_open
        .maps
        .frag6_cache_lan
        .reuse_fd(tc6.maps.frag6_cache_lan.as_fd())
        .expect("xdp_nat6 reuse frag6_cache_lan");
    xdp6_open
        .maps
        .frag6_cache_wan
        .reuse_fd(tc6.maps.frag6_cache_wan.as_fd())
        .expect("xdp_nat6 reuse frag6_cache_wan");
    let xdp6 = xdp6_open.load().expect("load xdp_nat6");

    let central_frag4_lan =
        MapHandle::from_pinned_path(&paths.frag4_cache_lan).expect("open frag4 lan pin");
    let central_frag4_wan =
        MapHandle::from_pinned_path(&paths.frag4_cache_wan).expect("open frag4 wan pin");
    let central_frag6_lan =
        MapHandle::from_pinned_path(&paths.frag6_cache_lan).expect("open frag6 lan pin");
    let central_frag6_wan =
        MapHandle::from_pinned_path(&paths.frag6_cache_wan).expect("open frag6 wan pin");

    assert_eq!(map_id(&root.maps.frag4_cache_lan), map_id(&central_frag4_lan));
    assert_eq!(map_id(&root.maps.frag4_cache_wan), map_id(&central_frag4_wan));
    assert_eq!(map_id(&root.maps.frag6_cache_lan), map_id(&central_frag6_lan));
    assert_eq!(map_id(&root.maps.frag6_cache_wan), map_id(&central_frag6_wan));

    assert_eq!(map_id(&tc4.maps.frag4_cache_lan), map_id(&central_frag4_lan));
    assert_eq!(map_id(&tc4.maps.frag4_cache_wan), map_id(&central_frag4_wan));
    assert_eq!(map_id(&xdp4.maps.frag4_cache_lan), map_id(&central_frag4_lan));
    assert_eq!(map_id(&xdp4.maps.frag4_cache_wan), map_id(&central_frag4_wan));

    assert_eq!(map_id(&tc6.maps.frag6_cache_lan), map_id(&central_frag6_lan));
    assert_eq!(map_id(&tc6.maps.frag6_cache_wan), map_id(&central_frag6_wan));
    assert_eq!(map_id(&xdp6.maps.frag6_cache_lan), map_id(&central_frag6_lan));
    assert_eq!(map_id(&xdp6.maps.frag6_cache_wan), map_id(&central_frag6_wan));
}
