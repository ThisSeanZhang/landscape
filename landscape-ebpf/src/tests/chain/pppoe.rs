use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::skel::tc_pppoe::types::pppoe_egress_tmpl;

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
    let builder = crate::skel::tc_pppoe::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let skel = open.load().unwrap();

    let plain_pkt = build_ipv4_packet();
    let mut output = vec![0u8; plain_pkt.len() + 8];

    skel.progs
        .tc_pppoe_wan_egress_v4
        .test_run(ProgramInput {
            data_in: Some(&plain_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_pppoe_wan_egress_v4 ipv4");

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
    let builder = crate::skel::tc_pppoe::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let skel = open.load().unwrap();

    let plain_pkt = build_ipv6_packet();
    let mut output = vec![0u8; plain_pkt.len() + 8];

    skel.progs
        .tc_pppoe_wan_egress_v6
        .test_run(ProgramInput {
            data_in: Some(&plain_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_pppoe_wan_egress_v6 ipv6");

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

// The non-IP guard moved from the stage up to the chain root: the root
// forks once on the L3 protocol and non-IP packets take no tail call,
// so stage entries only ever see their own family and trust their slot
// (see tc_wan_egress_root.bpf.c / tc_stage.h).
#[test]
fn pppoe_stage_non_ip_is_filtered_by_chain_root() {
    let stage_builder = crate::skel::tc_pppoe::TcPppoeSkelBuilder::default();
    let mut stage_object = MaybeUninit::uninit();
    let mut stage_open = stage_builder.open(&mut stage_object).unwrap();
    stage_open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = default_tmpl(SESSION_ID);
    let stage = stage_open.load().unwrap();

    let root_builder = crate::skel::tc_wan_egress_root::TcWanEgressRootSkelBuilder::default();
    let mut root_object = MaybeUninit::uninit();
    let root = root_builder.open(&mut root_object).unwrap().load().unwrap();

    // Wire the root's v4 fork slot to the stage, like the chain's tc relink.
    let stage_v4_fd = stage.progs.tc_pppoe_wan_egress_v4.as_fd().as_raw_fd();
    root.maps
        .wan_egress_root_next_stage
        .update(&0u32.to_ne_bytes(), &stage_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // Non-IP (ARP): the root must not enter the chain, packet unchanged.
    let arp_pkt = [
        0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0, 0xA8,
        0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0xA8, 0x01, 0x02,
    ]
    .to_vec();
    let original = arp_pkt.clone();
    let mut output = vec![0u8; arp_pkt.len() + 8];

    root.progs
        .tc_wan_egress_root
        .test_run(ProgramInput {
            data_in: Some(&arp_pkt),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run tc_wan_egress_root non-ip");

    assert_eq!(&output[..original.len()], &original[..], "non-IP must bypass the chain");

    // IPv4: the root forks into slot 0 and the stage encapsulates.
    let ip_pkt = build_ipv4_packet();
    let mut enc_out = vec![0u8; ip_pkt.len() + 8];

    root.progs
        .tc_wan_egress_root
        .test_run(ProgramInput {
            data_in: Some(&ip_pkt),
            data_out: Some(&mut enc_out),
            ..Default::default()
        })
        .expect("test_run tc_wan_egress_root ipv4");

    assert_eq!(enc_out[12], 0x88, "encapsulated ethertype 0x8864");
    assert_eq!(enc_out[13], 0x64);
    assert_eq!(&enc_out[22..ip_pkt.len() + 8], &ip_pkt[14..], "payload preserved");
}

#[test]
fn pppoe_session_id_is_set_in_rodata() {
    let builder = crate::skel::tc_pppoe::TcPppoeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
    rodata.pppoe_tmpl = default_tmpl(SESSION_ID);
    assert_eq!(rodata.pppoe_tmpl.session_id, SESSION_ID.to_be());
    let skel = open.load().unwrap();

    // Verify program loaded: simple test_run on empty data should work.
    // The v4 entry trusts its family slot and encapsulates unconditionally,
    // so leave room for the 8-byte PPPoE header.
    let empty = vec![0u8; 64];
    let mut out = vec![0u8; 64 + 8];
    skel.progs
        .tc_pppoe_wan_egress_v4
        .test_run(ProgramInput {
            data_in: Some(&empty),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("tc_pppoe_wan_egress_v4 test_run");
}
