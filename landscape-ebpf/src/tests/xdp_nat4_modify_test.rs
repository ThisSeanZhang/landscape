use std::mem::MaybeUninit;
use std::path::PathBuf;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::tests::test_xdp_nat4_modify_skel::TestXdpNat4ModifySkelBuilder;

const OUTER_IP_OFFSET: usize = 14;
const OUTER_ICMP_OFFSET: usize = OUTER_IP_OFFSET + 20;
const INNER_IP_OFFSET: usize = OUTER_ICMP_OFFSET + 8;
const INNER_ICMP_OFFSET: usize = INNER_IP_OFFSET + 20;
const INNER_TCP_OFFSET: usize = INNER_IP_OFFSET + 20;

const LAN_IP: [u8; 4] = [192, 168, 1, 100];
const WAN_IP: [u8; 4] = [203, 0, 113, 1];
const REMOTE_IP: [u8; 4] = [198, 51, 100, 20];
const ROUTER_IP: [u8; 4] = [198, 51, 100, 1];
const ORIGINAL_ID: u16 = 0x1234;
const NAT_ID: u16 = 0x5678;
const REMOTE_PORT: u16 = 443;
const ECHO_SEQUENCE: u16 = 7;

fn pin_root() -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-nat4-modify-{}-{}",
        std::process::id(),
        crate::tests::test_id()
    ));
    std::fs::create_dir_all(&path).expect("create test pin root");
    path
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}

fn write_ipv4_header(
    packet: &mut [u8],
    offset: usize,
    src: [u8; 4],
    dst: [u8; 4],
    len: u16,
    protocol: u8,
) {
    let ip = &mut packet[offset..offset + 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&len.to_be_bytes());
    ip[4..6].copy_from_slice(&1u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);
    let checksum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn build_icmp_error(
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    echo_id: u16,
) -> Vec<u8> {
    let mut packet = vec![0u8; INNER_ICMP_OFFSET + 8];
    packet[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    packet[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let inner_len = (20 + 8) as u16;
    write_ipv4_header(&mut packet, INNER_IP_OFFSET, inner_src, inner_dst, inner_len, 1);

    let inner_icmp = &mut packet[INNER_ICMP_OFFSET..INNER_ICMP_OFFSET + 8];
    inner_icmp[0] = 8;
    inner_icmp[4..6].copy_from_slice(&echo_id.to_be_bytes());
    inner_icmp[6..8].copy_from_slice(&ECHO_SEQUENCE.to_be_bytes());
    let inner_icmp_checksum = internet_checksum(inner_icmp);
    inner_icmp[2..4].copy_from_slice(&inner_icmp_checksum.to_be_bytes());

    let outer_icmp = &mut packet[OUTER_ICMP_OFFSET..];
    outer_icmp[0] = 3;
    outer_icmp[1] = 1;
    let outer_icmp_checksum = internet_checksum(outer_icmp);
    outer_icmp[2..4].copy_from_slice(&outer_icmp_checksum.to_be_bytes());

    let outer_len = (packet.len() - OUTER_IP_OFFSET) as u16;
    write_ipv4_header(&mut packet, OUTER_IP_OFFSET, outer_src, outer_dst, outer_len, 1);
    packet
}

fn tcp_checksum_ipv4(src: [u8; 4], dst: [u8; 4], tcp: &[u8]) -> u16 {
    let mut input = Vec::with_capacity(12 + tcp.len());
    input.extend_from_slice(&src);
    input.extend_from_slice(&dst);
    input.extend_from_slice(&[0, 6]);
    input.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    input.extend_from_slice(tcp);
    internet_checksum(&input)
}

fn build_tcp_icmp_error(
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    inner_source_port: u16,
    inner_dest_port: u16,
    tcp_quote_len: usize,
) -> Vec<u8> {
    assert!(tcp_quote_len <= 20);
    let mut packet = vec![0u8; INNER_TCP_OFFSET + tcp_quote_len];
    packet[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    packet[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    write_ipv4_header(&mut packet, INNER_IP_OFFSET, inner_src, inner_dst, 40, 6);

    let tcp = &mut packet[INNER_TCP_OFFSET..];
    if tcp_quote_len >= 2 {
        tcp[0..2].copy_from_slice(&inner_source_port.to_be_bytes());
    }
    if tcp_quote_len >= 4 {
        tcp[2..4].copy_from_slice(&inner_dest_port.to_be_bytes());
    }
    if tcp_quote_len >= 8 {
        tcp[4..8].copy_from_slice(&0x10203040u32.to_be_bytes());
    }
    if tcp_quote_len == 20 {
        tcp[12] = 0x50;
        tcp[13] = 0x10;
        tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
        let checksum = tcp_checksum_ipv4(inner_src, inner_dst, tcp);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
    }

    let outer_icmp = &mut packet[OUTER_ICMP_OFFSET..];
    outer_icmp[0] = 3;
    outer_icmp[1] = 1;
    let outer_icmp_checksum = internet_checksum(outer_icmp);
    outer_icmp[2..4].copy_from_slice(&outer_icmp_checksum.to_be_bytes());

    let outer_len = (packet.len() - OUTER_IP_OFFSET) as u16;
    write_ipv4_header(&mut packet, OUTER_IP_OFFSET, outer_src, outer_dst, outer_len, 1);
    packet
}

fn assert_valid_modified_packet(
    packet: &[u8],
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    echo_id: u16,
) {
    assert_eq!(&packet[26..30], &outer_src);
    assert_eq!(&packet[30..34], &outer_dst);
    assert_eq!(&packet[54..58], &inner_src);
    assert_eq!(&packet[58..62], &inner_dst);
    assert_eq!(packet[INNER_ICMP_OFFSET], 8);
    assert_eq!(u16::from_be_bytes(packet[66..68].try_into().unwrap()), echo_id);
    assert_eq!(u16::from_be_bytes(packet[68..70].try_into().unwrap()), ECHO_SEQUENCE);

    assert_eq!(internet_checksum(&packet[OUTER_IP_OFFSET..OUTER_ICMP_OFFSET]), 0);
    assert_eq!(internet_checksum(&packet[INNER_IP_OFFSET..INNER_ICMP_OFFSET]), 0);
    assert_eq!(internet_checksum(&packet[INNER_ICMP_OFFSET..]), 0);
    assert_eq!(internet_checksum(&packet[OUTER_ICMP_OFFSET..]), 0);
}

fn assert_valid_modified_tcp_packet(
    packet: &[u8],
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    inner_source_port: u16,
    inner_dest_port: u16,
    has_tcp_checksum: bool,
) {
    assert_eq!(&packet[26..30], &outer_src);
    assert_eq!(&packet[30..34], &outer_dst);
    assert_eq!(&packet[54..58], &inner_src);
    assert_eq!(&packet[58..62], &inner_dst);
    assert_eq!(
        u16::from_be_bytes(packet[INNER_TCP_OFFSET..INNER_TCP_OFFSET + 2].try_into().unwrap()),
        inner_source_port
    );
    assert_eq!(
        u16::from_be_bytes(packet[INNER_TCP_OFFSET + 2..INNER_TCP_OFFSET + 4].try_into().unwrap()),
        inner_dest_port
    );
    assert_eq!(&packet[INNER_TCP_OFFSET + 4..INNER_TCP_OFFSET + 8], &0x10203040u32.to_be_bytes());

    assert_eq!(internet_checksum(&packet[OUTER_IP_OFFSET..OUTER_ICMP_OFFSET]), 0);
    assert_eq!(internet_checksum(&packet[INNER_IP_OFFSET..INNER_TCP_OFFSET]), 0);
    assert_eq!(internet_checksum(&packet[OUTER_ICMP_OFFSET..]), 0);
    if has_tcp_checksum {
        assert_eq!(tcp_checksum_ipv4(inner_src, inner_dst, &packet[INNER_TCP_OFFSET..]), 0);
    }
}

#[test]
fn xdp_modify_icmp_error_egress_rewrites_inner_echo_id() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet = build_icmp_error(LAN_IP, REMOTE_IP, REMOTE_IP, LAN_IP, ORIGINAL_ID);
    let mut output = vec![0u8; packet.len()];
    let result = skel
        .progs
        .test_xdp_nat4_modify_icmp_error_egress
        .test_run(ProgramInput {
            data_in: Some(&mut packet),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
    assert_valid_modified_packet(&output, WAN_IP, REMOTE_IP, REMOTE_IP, WAN_IP, NAT_ID);
}

#[test]
fn xdp_modify_icmp_error_ingress_restores_inner_echo_id() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet = build_icmp_error(ROUTER_IP, WAN_IP, WAN_IP, REMOTE_IP, NAT_ID);
    let mut output = vec![0u8; packet.len()];
    let result = skel
        .progs
        .test_xdp_nat4_modify_icmp_error_ingress
        .test_run(ProgramInput {
            data_in: Some(&mut packet),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
    assert_valid_modified_packet(&output, ROUTER_IP, LAN_IP, LAN_IP, REMOTE_IP, ORIGINAL_ID);
}

#[test]
fn xdp_read_icmp_error_with_min_tcp_quote() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet =
        build_tcp_icmp_error(LAN_IP, REMOTE_IP, REMOTE_IP, LAN_IP, REMOTE_PORT, ORIGINAL_ID, 8);
    let result = skel
        .progs
        .test_xdp_nat4_read_icmp_error_tcp_quote
        .test_run(ProgramInput { data_in: Some(&mut packet), ..Default::default() })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
}

#[test]
fn xdp_read_icmp_error_rejects_incomplete_tcp_ports() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet =
        build_tcp_icmp_error(LAN_IP, REMOTE_IP, REMOTE_IP, LAN_IP, REMOTE_PORT, ORIGINAL_ID, 3);
    let result = skel
        .progs
        .test_xdp_nat4_read_icmp_error_tcp_quote
        .test_run(ProgramInput { data_in: Some(&mut packet), ..Default::default() })
        .expect("test_run failed");

    assert_eq!(result.return_value, 1);
}

#[test]
fn xdp_modify_icmp_error_egress_accepts_min_tcp_quote() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet =
        build_tcp_icmp_error(LAN_IP, REMOTE_IP, REMOTE_IP, LAN_IP, REMOTE_PORT, ORIGINAL_ID, 8);
    let mut output = vec![0u8; packet.len()];
    let result = skel
        .progs
        .test_xdp_nat4_modify_icmp_error_tcp_egress
        .test_run(ProgramInput {
            data_in: Some(&mut packet),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
    assert_valid_modified_tcp_packet(
        &output,
        WAN_IP,
        REMOTE_IP,
        REMOTE_IP,
        WAN_IP,
        REMOTE_PORT,
        NAT_ID,
        false,
    );
}

#[test]
fn xdp_modify_icmp_error_ingress_accepts_min_tcp_quote() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet =
        build_tcp_icmp_error(ROUTER_IP, WAN_IP, WAN_IP, REMOTE_IP, NAT_ID, REMOTE_PORT, 8);
    let mut output = vec![0u8; packet.len()];
    let result = skel
        .progs
        .test_xdp_nat4_modify_icmp_error_tcp_ingress
        .test_run(ProgramInput {
            data_in: Some(&mut packet),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
    assert_valid_modified_tcp_packet(
        &output,
        ROUTER_IP,
        LAN_IP,
        LAN_IP,
        REMOTE_IP,
        ORIGINAL_ID,
        REMOTE_PORT,
        false,
    );
}

#[test]
fn xdp_modify_icmp_error_updates_quoted_tcp_checksum_when_present() {
    let mut builder = TestXdpNat4ModifySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root()).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    let mut packet =
        build_tcp_icmp_error(LAN_IP, REMOTE_IP, REMOTE_IP, LAN_IP, REMOTE_PORT, ORIGINAL_ID, 20);
    let mut output = vec![0u8; packet.len()];
    let result = skel
        .progs
        .test_xdp_nat4_modify_icmp_error_tcp_egress
        .test_run(ProgramInput {
            data_in: Some(&mut packet),
            data_out: Some(&mut output),
            ..Default::default()
        })
        .expect("test_run failed");

    assert_eq!(result.return_value, 2);
    assert_valid_modified_tcp_packet(
        &output,
        WAN_IP,
        REMOTE_IP,
        REMOTE_IP,
        WAN_IP,
        REMOTE_PORT,
        NAT_ID,
        true,
    );
}
