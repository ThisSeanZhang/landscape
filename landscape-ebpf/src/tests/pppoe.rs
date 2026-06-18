use std::mem::MaybeUninit;

use etherparse::PacketBuilder;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}

use tc_pppoe_skel::types::pppoe_egress_tmpl;

const SESSION_ID: u16 = 0x2233;

fn default_tmpl(session_id: u16) -> pppoe_egress_tmpl {
    pppoe_egress_tmpl {
        dmac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        smac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        eth_proto: 0x8864u16.to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: session_id.to_be(),
        ..Default::default()
    }
}

fn build_ipv4_packet() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    )
    .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
    .tcp(12345, 443, 0x1000_0000, 8192)
    .syn();
    let payload = [0x11, 0x22, 0x33];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).unwrap();
    packet
}

fn build_ipv6_packet() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    )
    .ipv6(
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        64,
    )
    .tcp(12345, 443, 0x1000_0000, 8192)
    .syn();
    let payload = [0x11, 0x22, 0x33];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).unwrap();
    packet
}

#[test]
fn pppoe_egress_ipv4_adds_pppoe_header() {
    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let skel = open.load().unwrap();

    let mut plain_pkt = build_ipv4_packet();
    let mut output = vec![0u8; plain_pkt.len() + 8];

    skel.progs
        .tc_pppoe_wan_egress
        .test_run(ProgramInput {
            data_in: Some(&mut plain_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_pppoe_wan_egress ipv4");

    assert_eq!(output[12], 0x88);
    assert_eq!(output[13], 0x64);
    assert_eq!(output[14], 0x11);
    assert_eq!(output[15], 0x00);
    assert_eq!(output[16], (SESSION_ID >> 8) as u8);
    assert_eq!(output[17], SESSION_ID as u8);
    assert_eq!(output[20], 0x00);
    assert_eq!(output[21], 0x21);
    assert_eq!(&output[22..plain_pkt.len() + 8], &plain_pkt[14..]);
}

#[test]
fn pppoe_egress_ipv6_adds_pppoe_header() {
    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let skel = open.load().unwrap();

    let mut plain_pkt = build_ipv6_packet();
    let mut output = vec![0u8; plain_pkt.len() + 8];

    skel.progs
        .tc_pppoe_wan_egress
        .test_run(ProgramInput {
            data_in: Some(&mut plain_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_pppoe_wan_egress ipv6");

    assert_eq!(output[12], 0x88);
    assert_eq!(output[13], 0x64);
    assert_eq!(output[14], 0x11);
    assert_eq!(output[15], 0x00);
    assert_eq!(output[16], (SESSION_ID >> 8) as u8);
    assert_eq!(output[17], SESSION_ID as u8);
    assert_eq!(output[20], 0x00);
    assert_eq!(output[21], 0x57);
    assert_eq!(&output[22..plain_pkt.len() + 8], &plain_pkt[14..]);
}

#[test]
fn pppoe_egress_non_ip_passes_unchanged() {
    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let skel = open.load().unwrap();

    let mut arp_pkt = [
        0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0, 0xA8,
        0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0xA8, 0x01, 0x02,
    ]
    .to_vec();
    let original = arp_pkt.clone();
    let mut output = vec![0u8; arp_pkt.len() + 8];

    skel.progs
        .tc_pppoe_wan_egress
        .test_run(ProgramInput {
            data_in: Some(&mut arp_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_pppoe_wan_egress non-ip");

    assert_eq!(&output[..original.len()], &original[..]);
}

#[test]
fn pppoe_session_id_is_set_in_rodata() {
    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
    rodata.pppoe_tmpl = default_tmpl(SESSION_ID);
    assert_eq!(rodata.pppoe_tmpl.session_id, SESSION_ID.to_be());
    let skel = open.load().unwrap();

    // Verify program loaded: simple test_run on empty data should work
    let mut empty = vec![0u8; 64];
    let mut out = vec![0u8; 64];
    skel.progs
        .tc_pppoe_wan_egress
        .test_run(ProgramInput {
            data_in: Some(&mut empty),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("tc_pppoe_wan_egress test_run");
}
