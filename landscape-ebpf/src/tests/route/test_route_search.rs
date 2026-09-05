use std::{mem::MaybeUninit, net::IpAddr};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::{
    maps::wan::add_wan_ip,
    tests::{
        isolated_pin_root,
        route::{
            map_helper::{
                create_route6_cache_inner_map, gateway_addr, insert_ip_mac_v6, local_addr,
                put_rt6_cache_ifindex, remote_addr, wan_addr, TARGET_IFINDEX, WAN_CACHE,
            },
            packet_builder::simple_ipv6_tcp_syn,
            test_route::TestRouteSkelBuilder,
        },
    },
};

#[test]
fn v6_search_cache_in_lan_uses_ip_mac_v6() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-search");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_ifindex(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
    );
    add_wan_ip(
        &skel.maps.wan_ip_binding,
        TARGET_IFINDEX,
        wan_addr(),
        Some(IpAddr::V6(gateway_addr())),
        64,
        None,
    );

    let next_hop_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, remote_addr(), next_hop_mac, dev_mac, TARGET_IFINDEX);

    let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let mut packet_out = vec![0_u8; packet.len()];
    let result = skel
        .progs
        .test_route_v6_search_cache_in_lan
        .test_run(ProgramInput {
            data_in: Some(&packet),
            data_out: Some(&mut packet_out),
            ..Default::default()
        })
        .expect("run test_route_v6_search_cache_in_lan");

    assert_eq!(result.return_value as i32, 7);
    assert_eq!(&packet_out[0..6], &next_hop_mac.octets());
    assert_eq!(&packet_out[6..12], &dev_mac.octets());
    assert_eq!(&packet_out[12..14], &[0x86, 0xdd]);
}

#[test]
fn v6_search_cache_in_lan_falls_back_to_gateway_mac() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-gateway-fallback");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    create_route6_cache_inner_map(&skel.maps.rt6_cache_map, WAN_CACHE);
    put_rt6_cache_ifindex(
        &skel.maps.rt6_cache_map,
        WAN_CACHE,
        local_addr(),
        remote_addr(),
        TARGET_IFINDEX,
        true,
    );
    add_wan_ip(
        &skel.maps.wan_ip_binding,
        TARGET_IFINDEX,
        wan_addr(),
        Some(IpAddr::V6(gateway_addr())),
        64,
        None,
    );

    let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
    let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
    insert_ip_mac_v6(&skel.maps.ip_mac_v6, gateway_addr(), gateway_mac, dev_mac, TARGET_IFINDEX);

    let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
    let mut packet_out = vec![0_u8; packet.len()];
    let result = skel
        .progs
        .test_route_v6_search_cache_in_lan
        .test_run(ProgramInput {
            data_in: Some(&packet),
            data_out: Some(&mut packet_out),
            ..Default::default()
        })
        .expect("run test_route_v6_search_cache_in_lan gateway fallback");

    assert_eq!(result.return_value as i32, 7);
    assert_eq!(&packet_out[0..6], &gateway_mac.octets());
    assert_eq!(&packet_out[6..12], &dev_mac.octets());
    assert_eq!(&packet_out[12..14], &[0x86, 0xdd]);
}
