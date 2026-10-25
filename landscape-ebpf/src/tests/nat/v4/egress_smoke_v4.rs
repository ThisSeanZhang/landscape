use std::net::Ipv4Addr;

use super::common::{run, with_skel_wan};

const WAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 101, 201);

pub fn run_ipv4_egress_smoke(payload: Vec<u8>) {
    with_skel_wan(WAN_IP, &[], &[], &[], |skel| {
        let (return_value, packet_out) = run(&skel.progs.tc_v4_from_lan, &payload);

        println!("return_value = {return_value}");
        println!("packet_out = {packet_out:?}");
        crate::tests::helper::check::analyze(&packet_out);
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::pkt::capture_ipv4_tcp_syn;

    #[test]
    fn tcp_syn_smoke_v4() {
        run_ipv4_egress_smoke(capture_ipv4_tcp_syn());
    }
}
