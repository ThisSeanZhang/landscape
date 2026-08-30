use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::stages::firewall::tc_firewall_skel::TcFirewallSkelBuilder;

mod package;

pub fn test_ingress_and_egress(egress_payload: Vec<u8>, ingress_payload: Vec<u8>) {
    let mut firewall_open_object = MaybeUninit::zeroed();
    let firewall_builder = TcFirewallSkelBuilder::default();

    let firewall_open_skel = firewall_builder.open(&mut firewall_open_object).unwrap();

    let repeat = 10_000;

    let skel = firewall_open_skel.load().unwrap();

    let egress_firewall = skel.progs.tc_firewall_wan_egress;
    let ingress_firewall = skel.progs.tc_firewall_wan_ingress;

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
    use crate::tests::tc_chain::firewall::{
        package::{icmpv6_ping_egress, icmpv6_ping_ingress},
        test_ingress_and_egress,
    };

    #[test]
    fn test() {
        test_ingress_and_egress(icmpv6_ping_egress(), icmpv6_ping_ingress());
    }
}
