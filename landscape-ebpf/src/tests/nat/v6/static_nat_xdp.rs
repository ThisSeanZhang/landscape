use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use etherparse::{PacketBuilder, PacketHeaders};
use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::{
    map_setting::{add_wan_ip, nat::StaticNatMappingV6Item},
    tests::xdp_nat_skel::XdpNatSkelBuilder,
};

const IFINDEX: u32 = 6;
const XDP_PASS: u32 = 2;

fn wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::100").unwrap()
}

fn wan_npt_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap()
}

fn local_target() -> Ipv6Addr {
    Ipv6Addr::from_str("::cafe").unwrap()
}

fn local_wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::cafe").unwrap()
}

fn remote() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
}

fn build_ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .udp(src_port, dst_port);
    let mut packet = Vec::with_capacity(builder.size(8));
    builder.write(&mut packet, &[0; 8]).unwrap();
    packet
}

fn packet_source(packet: &[u8]) -> Ipv6Addr {
    let parsed = PacketHeaders::from_ethernet_slice(packet_data(packet)).expect("parse output");
    let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
        panic!("expected IPv6 output");
    };
    ipv6.source.into()
}

fn packet_destination(packet: &[u8]) -> Ipv6Addr {
    let parsed = PacketHeaders::from_ethernet_slice(packet_data(packet)).expect("parse output");
    let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
        panic!("expected IPv6 output");
    };
    ipv6.destination.into()
}

fn packet_data(output: &[u8]) -> &[u8] {
    if output.get(12..14) == Some(&[0x86, 0xdd]) {
        output
    } else {
        &output[8..]
    }
}

fn assert_xdp_round_trip(
    name: &str,
    static_target: Option<Ipv6Addr>,
    client_address: Ipv6Addr,
    external_address: Ipv6Addr,
    client_port: u16,
) {
    let mut builder = XdpNatSkelBuilder::default();
    let pin_root = crate::tests::nat::isolated_pin_root(name);
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = IFINDEX;
    let skel = open_skel.load().unwrap();

    add_wan_ip(
        &skel.maps.wan_ip_binding,
        IFINDEX,
        IpAddr::V6(wan_ip()),
        None,
        60,
        Some(MacAddr::broadcast()),
    );
    if let Some(target) = static_target {
        crate::map_setting::nat::add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: client_port, lan_ip: target, l4_protocol: 17 }],
        );
    }

    let egress = build_ipv6_udp(client_address, remote(), client_port, 9999);
    let mut egress_out = vec![0; egress.len() + 8];
    let result = skel
        .progs
        .egress_nat
        .test_run(ProgramInput {
            data_in: Some(&egress),
            data_out: Some(&mut egress_out),
            ..Default::default()
        })
        .expect("egress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);
    assert_eq!(packet_source(result.data.as_deref().unwrap()), external_address);

    let ingress = build_ipv6_udp(remote(), external_address, 9999, client_port);
    let mut ingress_out = vec![0; ingress.len() + 8];
    let result = skel
        .progs
        .ingress_nat
        .test_run(ProgramInput {
            data_in: Some(&ingress),
            data_out: Some(&mut ingress_out),
            ..Default::default()
        })
        .expect("ingress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);
    assert_eq!(packet_destination(result.data.as_deref().unwrap()), client_address);
}

#[test]
fn xdp_zero_prefix_static_passes_both_directions() {
    assert_xdp_round_trip(
        "nat-v6-xdp-static-pass",
        Some(local_target()),
        local_wan_ip(),
        local_wan_ip(),
        53,
    );
}

#[test]
fn xdp_nonzero_prefix_static_replaces_both_directions() {
    assert_xdp_round_trip(
        "nat-v6-xdp-static-replace",
        Some(lan_host()),
        lan_host(),
        wan_npt_addr(),
        80,
    );
}

#[test]
fn xdp_dynamic_flow_replaces_both_directions() {
    assert_xdp_round_trip("nat-v6-xdp-dynamic", None, lan_host(), wan_npt_addr(), 12345);
}
