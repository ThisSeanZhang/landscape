use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::tests::pkt::*;
use crate::tests::tc_nat4_v4_skel::TcNat4V4SkelBuilder;

const TC_ACT_UNSPEC: i32 = -1;
const TC_ACT_SHOT: i32 = 2;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn run_lan(pkt: &mut [u8]) -> i32 {
    let builder = TcNat4V4SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = 14;
        rodata.land_nat_external_addr = u32::from_ne_bytes(WAN_IP.octets());
        rodata.land_nat_udp_range_start = 32768;
        rodata.land_nat_udp_range_end = 65535;
        rodata.land_nat_tcp_range_start = 32768;
        rodata.land_nat_tcp_range_end = 65535;
    }
    let skel = open.load().unwrap();

    let input = ProgramInput { data_in: Some(pkt), ..Default::default() };
    skel.progs.tc_v4_from_lan.test_run(input).expect("test_run failed").return_value as i32
}

#[test]
fn loads_and_reaches_lan_state_stage() {
    let mut pkt = simple_ipv4_udp(LAN_HOST, REMOTE_IP);
    assert_eq!(run_lan(&mut pkt), TC_ACT_SHOT);
}

#[test]
fn passes_non_ipv4() {
    let mut pkt = build_ipv6_udp_eth();
    assert_eq!(run_lan(&mut pkt), TC_ACT_UNSPEC);
}
