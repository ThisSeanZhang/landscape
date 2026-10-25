use std::{mem::MaybeUninit, net::Ipv6Addr, str::FromStr};

use etherparse::{IcmpEchoHeader, Icmpv6Type, PacketBuilder, PacketHeaders};
use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::maps::nat::StaticNatMappingV6Item;
use crate::skel::xdp_nat6::XdpNat6SkelBuilder;

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

fn build_ipv6_icmpv6_echo(src: Ipv6Addr, dst: Ipv6Addr, id: u16, request: bool) -> Vec<u8> {
    let echo = IcmpEchoHeader { id, seq: 1 };
    let ty = if request { Icmpv6Type::EchoRequest(echo) } else { Icmpv6Type::EchoReply(echo) };
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .icmpv6(ty);
    let mut packet = Vec::with_capacity(builder.size(0));
    builder.write(&mut packet, &[]).unwrap();
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

/// sizeof(struct xdp_pipe_meta): BPF_PROG_TEST_RUN copies the XDP
/// metadata area into data_out as a prefix of the returned packet
/// (test_run.c: size = data_end - data_meta), and the ingress static
/// path allocates it via bpf_xdp_adjust_meta.
const XDP_PIPE_META_LEN: usize = 12;

fn packet_data(output: &[u8]) -> &[u8] {
    if output.get(12..14) == Some(&[0x86, 0xdd]) { output } else { &output[XDP_PIPE_META_LEN..] }
}

fn assert_xdp_round_trip(
    name: &str,
    static_target: Option<Ipv6Addr>,
    client_address: Ipv6Addr,
    external_address: Ipv6Addr,
    client_port: u16,
) {
    let mut builder = XdpNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root(name);
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
    }
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = IFINDEX;
    let skel = open_skel.load().unwrap();
    if let Some(target) = static_target {
        crate::maps::nat::add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: client_port, lan_ip: target, l4_protocol: 17 }],
        );
    }

    let egress = build_ipv6_udp(client_address, remote(), client_port, 9999);
    let mut egress_out = vec![0; egress.len() + 8];
    let result = skel
        .progs
        .egress_nat_v6
        .test_run(ProgramInput {
            data_in: Some(&egress),
            data_out: Some(&mut egress_out),
            ..Default::default()
        })
        .expect("egress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);
    assert_eq!(packet_source(result.data.as_deref().unwrap()), external_address);

    let ingress = build_ipv6_udp(remote(), external_address, 9999, client_port);
    // room for the 12-byte meta prefix the static-ingress path appends
    let mut ingress_out = vec![0; ingress.len() + XDP_PIPE_META_LEN];
    let result = skel
        .progs
        .ingress_nat_v6
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
fn xdp_icmpv6_echo_round_trip() {
    let mut builder = XdpNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-xdp-echo");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
    }
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = IFINDEX;
    let skel = open_skel.load().unwrap();

    let id = 0x1234;
    let request = build_ipv6_icmpv6_echo(lan_host(), remote(), id, true);
    let mut out = vec![0; request.len()];
    let result = skel
        .progs
        .egress_nat_v6
        .test_run(ProgramInput {
            data_in: Some(&request),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("egress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);
    assert_eq!(packet_source(result.data.as_deref().unwrap()), wan_npt_addr());

    let reply = build_ipv6_icmpv6_echo(remote(), wan_npt_addr(), id, false);
    let mut out = vec![0; reply.len() + XDP_PIPE_META_LEN];
    let result = skel
        .progs
        .ingress_nat_v6
        .test_run(ProgramInput {
            data_in: Some(&reply),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("ingress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);
    assert_eq!(packet_destination(result.data.as_deref().unwrap()), lan_host());
}

#[test]
fn xdp_dynamic_flow_without_ethernet() {
    let mut builder = XdpNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-xdp-noeth");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
        rodata.current_l3_offset = 0;
    }
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = IFINDEX;
    let skel = open_skel.load().unwrap();

    let egress = build_ipv6_udp(lan_host(), remote(), 12345, 9999);
    let egress = &egress[14..];
    let mut egress_out = vec![0; egress.len()];
    let result = skel
        .progs
        .egress_nat_v6
        .test_run(ProgramInput {
            data_in: Some(egress),
            data_out: Some(&mut egress_out),
            ..Default::default()
        })
        .expect("egress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);

    let parsed = PacketHeaders::from_ip_slice(result.data.as_deref().unwrap()).unwrap();
    let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
        panic!("expected raw IPv6 egress output");
    };
    assert_eq!(Ipv6Addr::from(ipv6.source), wan_npt_addr());

    let ingress = build_ipv6_udp(remote(), wan_npt_addr(), 9999, 12345);
    let ingress = &ingress[14..];
    let mut ingress_out = vec![0; ingress.len()];
    let result = skel
        .progs
        .ingress_nat_v6
        .test_run(ProgramInput {
            data_in: Some(ingress),
            data_out: Some(&mut ingress_out),
            ..Default::default()
        })
        .expect("ingress test_run failed");
    assert_eq!(result.return_value, XDP_PASS);

    let parsed = PacketHeaders::from_ip_slice(result.data.as_deref().unwrap()).unwrap();
    let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
        panic!("expected raw IPv6 ingress output");
    };
    assert_eq!(Ipv6Addr::from(ipv6.destination), lan_host());
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
