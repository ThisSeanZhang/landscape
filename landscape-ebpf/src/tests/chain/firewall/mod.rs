use std::mem::MaybeUninit;

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::skel::tc_firewall::TcFirewallSkelBuilder;

mod package;

pub fn test_ingress_and_egress(egress_payload: Vec<u8>, ingress_payload: Vec<u8>) {
    let mut firewall_open_object = MaybeUninit::zeroed();
    let firewall_builder = TcFirewallSkelBuilder::default();

    let firewall_open_skel = firewall_builder.open(&mut firewall_open_object).unwrap();

    let repeat = 10_000;

    let skel = firewall_open_skel.load().unwrap();

    let egress_firewall = skel.progs.tc_firewall_wan_egress_v4;
    let ingress_firewall = skel.progs.tc_firewall_wan_ingress_v4;

    let egress_input = ProgramInput {
        data_in: Some(&egress_payload),
        context_in: None,
        context_out: None,
        data_out: None,
        repeat,
        ..Default::default()
    };
    let result = egress_firewall.test_run(egress_input).expect("test_run failed");

    assert_eq!(result.return_value as i32, -1);
    println!("time: {}", result.duration.as_nanos());

    let ingress_input = ProgramInput {
        data_in: Some(&ingress_payload),
        context_in: None,
        context_out: None,
        data_out: None,
        repeat,
        ..Default::default()
    };
    let result = ingress_firewall.test_run(ingress_input).expect("test_run failed");

    assert_eq!(result.return_value as i32, 0);
    println!("time: {}", result.duration.as_nanos());
}

#[cfg(test)]
pub mod tests {
    use std::mem::MaybeUninit;
    use std::net::Ipv4Addr;

    use libbpf_rs::{
        MapCore, MapFlags, ProgramInput,
        skel::{OpenSkel, SkelBuilder as _},
    };
    use zerocopy::IntoBytes;

    use super::TcFirewallSkelBuilder;
    use crate::tests::TestSkb;
    use crate::tests::chain::firewall::{
        package::{icmpv6_ping_egress, icmpv6_ping_ingress},
        test_ingress_and_egress,
    };
    use crate::tests::helper::map::{skip_route_and_stage_mark, skip_route_mark};
    use crate::tests::pkt::simple_ipv4_tcp;

    #[test]
    fn test() {
        test_ingress_and_egress(icmpv6_ping_egress(), icmpv6_ping_ingress());
    }

    #[test]
    fn skip_route_runs_firewall_but_skip_route_and_stage_does_not() {
        let mut obj = MaybeUninit::zeroed();
        let skel = TcFirewallSkelBuilder::default().open(&mut obj).unwrap().load().unwrap();

        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&32u32.to_ne_bytes());
        key[4..8].copy_from_slice(&[203, 0, 113, 1]);
        skel.maps.firewall_block_ip4_map.update(&key, &[1u8, 0, 0, 0], MapFlags::ANY).unwrap();

        let pkt = simple_ipv4_tcp(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(203, 0, 113, 1));
        let run = |mark: u32| {
            let mut ctx = TestSkb { mark, ..Default::default() };
            let mut ctx_out = TestSkb::default();
            let mut out = vec![0u8; pkt.len()];
            skel.progs
                .tc_firewall_wan_egress_v4
                .test_run(ProgramInput {
                    data_in: Some(&pkt),
                    data_out: Some(&mut out),
                    context_in: Some(ctx.as_mut_bytes()),
                    context_out: Some(ctx_out.as_mut_bytes()),
                    ..Default::default()
                })
                .expect("run tc_firewall_wan_egress_v4")
                .return_value as i32
        };

        assert_eq!(run(skip_route_mark(1)), 2, "SkipRoute must run the firewall block");
        assert_eq!(
            run(skip_route_and_stage_mark(1)),
            -1,
            "SkipRouteAndStage must skip the firewall"
        );
    }
}
