use std::{mem::MaybeUninit, net::Ipv6Addr, str::FromStr};

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::tests::pkt::{
    capture_icmpv6_udp_error, capture_ipv6_icmp_request, capture_ipv6_icmp_too_big,
    capture_ipv6_tcp_syn, capture_ipv6_tcp_syn_with_bad_checksum,
};
use crate::tests::{TestSkb, nat::test_nat6_v3::TestNat6V3SkelBuilder};

pub fn run_ipv6_egress_helper(payload: Vec<u8>) {
    let mut landscape_builder = TestNat6V3SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-egress-helper");
    landscape_builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut landscape_open = landscape_builder.open(&mut open_object).unwrap();
    {
        let rodata = landscape_open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(
            Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap(),
        ));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
    }

    let landscape_skel = landscape_open.load().unwrap();

    let ifindex = 6;

    let egress_helper = landscape_skel.progs.handle_ipv6_egress;

    let mut ctx = TestSkb { ifindex, ..Default::default() };

    let mut packet_out = vec![0u8; payload.len()];
    let input = ProgramInput {
        data_in: Some(&payload),
        context_in: Some(ctx.as_mut_bytes()),
        context_out: None,
        data_out: Some(&mut packet_out),
        ..Default::default()
    };
    let result = egress_helper.test_run(input).expect("test_run failed");

    println!("return_value = {}", result.return_value as i32);
    println!("duration = {:?}", result.duration);
    println!("packet_out = {:?}", packet_out);
    crate::tests::helper::check::analyze(&packet_out);
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn ipv6_icmp_too_big() {
        run_ipv6_egress_helper(capture_ipv6_icmp_too_big());
    }

    #[test]
    fn ipv6_icmp_request() {
        run_ipv6_egress_helper(capture_ipv6_icmp_request());
    }

    #[test]
    fn tcp_syn_helper_v6() {
        run_ipv6_egress_helper(capture_ipv6_tcp_syn());
    }

    #[test]
    fn tcp_syn_with_bad_checksum_helper_v6() {
        run_ipv6_egress_helper(capture_ipv6_tcp_syn_with_bad_checksum());
    }

    #[test]
    fn icmpv6_udp_error() {
        run_ipv6_egress_helper(capture_icmpv6_udp_error());
    }
}
