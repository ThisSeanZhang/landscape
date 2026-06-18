use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};
use zerocopy::IntoBytes;

use crate::{map_setting::add_wan_ip, stages::nat::tc_nat_skel::TcNatSkelBuilder, tests::TestSkb};

/// https://www.cloudshark.org/captures/456a264486bf?filter=tcp
/// 192.168.101.201:56186 -> 50.18.88.205:443
fn build_ipv4_tcp_syn() -> Vec<u8> {
    [
        0x00, 0x25, 0x90, 0x97, 0x4b, 0x8e, 0x00, 0x21, 0xcc, 0xd2, 0x9b, 0x82, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x34, 0x0a, 0x6d, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x65, 0xc9,
        0x32, 0x12, 0x58, 0xcd, 0xdb, 0x7a, 0x01, 0xbb, 0xc7, 0xde, 0x8e, 0xce, 0x00, 0x00, 0x00,
        0x00, 0x80, 0x02, 0x20, 0x00, 0xb1, 0x77, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03,
        0x03, 0x02, 0x01, 0x01, 0x04, 0x02,
    ]
    .to_vec()
}

pub fn run_ipv4_egress_smoke(mut payload: Vec<u8>) {
    let mut builder = TcNatSkelBuilder::default();
    let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-egress");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object).unwrap();

    let skel = open_skel.load().unwrap();

    let ifindex = 6;

    add_wan_ip(
        &skel.maps.wan_ip_binding,
        ifindex,
        IpAddr::V4(Ipv4Addr::new(192, 168, 101, 201)),
        None,
        24,
        Some(MacAddr::broadcast()),
    );
    let egress_nat = skel.progs.tc_nat_wan_egress;

    let mut ctx = TestSkb::default();
    ctx.ifindex = ifindex;

    let mut packet_out = vec![0u8; payload.len()];
    let input = ProgramInput {
        data_in: Some(&mut payload),
        context_in: Some(ctx.as_mut_bytes()),
        context_out: None,
        data_out: Some(&mut packet_out),
        ..Default::default()
    };
    let result = egress_nat.test_run(input).expect("test_run failed");

    println!("return_value = {}", result.return_value as i32);
    println!("duration = {:?}", result.duration);
    println!("packet_out = {:?}", packet_out);
    crate::tests::check::analyze(&packet_out);
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn tcp_syn_smoke_v4() {
        run_ipv4_egress_smoke(build_ipv4_tcp_syn());
    }
}
