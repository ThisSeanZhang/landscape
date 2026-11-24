use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::skel::tc_firewall::TcFirewallSkelBuilder;
use crate::skel::tc_wan_egress_exit::TcWanEgressExitSkel;
use crate::skel::tc_wan_egress_root::TcWanEgressRootSkelBuilder;
use crate::skel::tc_wan_pppoe_exit::TcWanPppoeExitSkel;
use crate::skel::tc_wan_pppoe_exit::types::pppoe_egress_tmpl;
use crate::tests::TestSkb;
use crate::tests::helper::map::{skip_route_and_stage_mark, skip_route_mark};

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

fn load_pppoe_exit(tmpl: pppoe_egress_tmpl) -> TcWanPppoeExitSkel<'static> {
    // The open object must outlive the loaded skeleton; leak it for the
    // test's lifetime.
    let object = Box::leak(Box::new(MaybeUninit::uninit()));
    let mut open =
        crate::skel::tc_wan_pppoe_exit::TcWanPppoeExitSkelBuilder::default().open(object).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = tmpl;
    open.load().unwrap()
}

fn load_plain_exit() -> TcWanEgressExitSkel<'static> {
    let object = Box::leak(Box::new(MaybeUninit::uninit()));
    crate::skel::tc_wan_egress_exit::TcWanEgressExitSkelBuilder::default()
        .open(object)
        .unwrap()
        .load()
        .unwrap()
}

fn build_ipv4_packet_to(dst: [u8; 4]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
    )
    .ipv4([10, 0, 0, 1], dst, 64)
    .tcp(12345, 443, 0x1000_0000, 8192)
    .syn();
    let payload = [0x11, 0x22, 0x33];
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, &payload).unwrap();
    packet
}

fn build_ipv4_packet() -> Vec<u8> {
    build_ipv4_packet_to([10, 0, 0, 2])
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

fn run_prog(prog: &libbpf_rs::ProgramMut<'_>, pkt: &[u8]) -> (i32, Vec<u8>) {
    // Room for the +8 encap when PPPoE is enabled.
    let mut out = vec![0u8; pkt.len() + 8];
    let ret = prog
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            ..Default::default()
        })
        .expect("test_run TC chain exit")
        .return_value as i32;
    (ret, out)
}

#[test]
fn pppoe_egress_ipv4_adds_pppoe_header() {
    let exit = load_pppoe_exit(default_tmpl(SESSION_ID));
    let plain_pkt = build_ipv4_packet();

    let (ret, output) = run_prog(&exit.progs.tc_wan_pppoe_exit_redirect, &plain_pkt);

    assert_eq!(ret, -1);
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
    let exit = load_pppoe_exit(default_tmpl(SESSION_ID));
    let plain_pkt = build_ipv6_packet();

    let (ret, output) = run_prog(&exit.progs.tc_wan_pppoe_exit_redirect, &plain_pkt);

    assert_eq!(ret, -1);
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
fn pppoe_exit_does_not_encapsulate_non_ip() {
    let exit = load_pppoe_exit(default_tmpl(SESSION_ID));
    let arp_pkt = [
        0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0, 0xA8,
        0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0xA8, 0x01, 0x02,
    ];

    let (ret, output) = run_prog(&exit.progs.tc_wan_pppoe_exit_redirect, &arp_pkt);

    assert_eq!(ret, -1);
    assert_eq!(&output[..arp_pkt.len()], &arp_pkt[..]);
}

#[test]
fn plain_exit_leaves_packets_untouched() {
    let exit = load_plain_exit();
    let pkt = build_ipv4_packet();

    let (ret, output) = run_prog(&exit.progs.tc_wan_egress_exit_redirect, &pkt);

    assert_eq!(ret, -1);
    assert_eq!(&output[..pkt.len()], &pkt[..]);
}

#[test]
fn chain_root_bypasses_non_ip_and_encapsulates_ip_on_the_exit() {
    let exit = load_pppoe_exit(default_tmpl(SESSION_ID));

    let root_builder = crate::skel::tc_wan_egress_root::TcWanEgressRootSkelBuilder::default();
    let mut root_object = MaybeUninit::uninit();
    let root = root_builder.open(&mut root_object).unwrap().load().unwrap();

    // Wire the root's v4 fork slot to the configured exit, like the chain's
    // tc relink does.
    let exit_v4_fd = exit.progs.tc_wan_pppoe_exit_redirect.as_fd().as_raw_fd();
    root.maps
        .tc_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_v4_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // Non-IP (ARP): the root must not enter the chain, packet unchanged.
    let arp_pkt = [
        0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0xC0, 0xA8,
        0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC0, 0xA8, 0x01, 0x02,
    ];
    let mut arp_out = vec![0u8; arp_pkt.len() + 8];
    root.progs
        .tc_wan_egress_root
        .test_run(ProgramInput {
            data_in: Some(&arp_pkt),
            data_out: Some(&mut arp_out),
            ..Default::default()
        })
        .expect("test_run tc_wan_egress_root non-ip");
    assert_eq!(&arp_out[..arp_pkt.len()], &arp_pkt[..], "non-IP must bypass the chain");

    // IPv4: the root forks into slot 0 and the terminal encapsulates.
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

fn assert_pppoe_frame(output: &[u8], plain: &[u8]) {
    assert_eq!(output[12], 0x88, "ethertype hi");
    assert_eq!(output[13], 0x64, "ethertype lo (PPPoE session)");
    assert_eq!(output[14], 0x11, "version/type");
    assert_eq!(output[16], (SESSION_ID >> 8) as u8, "session id hi");
    assert_eq!(output[17], SESSION_ID as u8, "session id lo");
    assert_eq!(output[20], 0x00, "PPP proto hi");
    assert_eq!(output[21], 0x21, "PPP proto lo (IPv4)");
    assert_eq!(&output[22..plain.len() + 8], &plain[14..], "L3 payload preserved");
}

#[test]
fn root_skip_route_bypasses_policy_but_keeps_pppoe_encap() {
    const BLOCKED: [u8; 4] = [203, 0, 113, 1];
    const ALLOWED: [u8; 4] = [198, 51, 100, 7];

    let exit = load_pppoe_exit(default_tmpl(SESSION_ID));
    let exit_fd = exit.progs.tc_wan_pppoe_exit_redirect.as_fd().as_raw_fd();

    let mut fw_object = MaybeUninit::zeroed();
    let fw = TcFirewallSkelBuilder::default().open(&mut fw_object).unwrap().load().unwrap();
    let mut key = [0u8; 8];
    key[0..4].copy_from_slice(&32u32.to_ne_bytes());
    key[4..8].copy_from_slice(&BLOCKED);
    fw.maps.firewall_block_ip4_map.update(&key, &[1u8, 0, 0, 0], MapFlags::ANY).unwrap();
    fw.maps
        .tc_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let mut root_object = MaybeUninit::zeroed();
    let root =
        TcWanEgressRootSkelBuilder::default().open(&mut root_object).unwrap().load().unwrap();
    let fw_v4 = fw.progs.tc_firewall_wan_egress_v4.as_fd().as_raw_fd();
    root.maps
        .wan_egress_root_next_stage
        .update(&0u32.to_ne_bytes(), &fw_v4.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    root.maps
        .tc_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let run = |pkt: &[u8], mark: u32| -> (i32, Vec<u8>) {
        let mut out = vec![0u8; pkt.len() + 8];
        let mut ctx = TestSkb { mark, ..Default::default() };
        let ret = root
            .progs
            .tc_wan_egress_root
            .test_run(ProgramInput {
                data_in: Some(pkt),
                data_out: Some(&mut out),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("test_run tc_wan_egress_root")
            .return_value as i32;
        (ret, out)
    };

    let blocked = build_ipv4_packet_to(BLOCKED);
    assert_eq!(run(&blocked, skip_route_mark(1)).0, 2, "SkipRoute must run the firewall");

    let (ret, out) = run(&blocked, skip_route_and_stage_mark(1));
    assert_eq!(ret, -1, "SkipRouteAndStage must bypass the firewall");
    assert_pppoe_frame(&out, &blocked);

    let allowed = build_ipv4_packet_to(ALLOWED);
    let (ret, out) = run(&allowed, skip_route_mark(1));
    assert_eq!(ret, -1, "SkipRoute that survives policy still reaches the exit");
    assert_pppoe_frame(&out, &allowed);
}
