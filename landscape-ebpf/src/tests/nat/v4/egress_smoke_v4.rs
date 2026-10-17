use std::{mem::MaybeUninit, net::Ipv4Addr};

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::skel::tc_nat4::TcNat4SkelBuilder;
use crate::tests::TestSkb;
use crate::tests::pkt::capture_ipv4_tcp_syn;

pub fn run_ipv4_egress_smoke(payload: Vec<u8>) {
    let mut builder = TcNat4SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v4-egress");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_addr4 = crate::stages::nat4::wan_ro_addr4(Ipv4Addr::new(192, 168, 101, 201));
    }

    let skel = open_skel.load().unwrap();

    let ifindex = 6;
    let egress_nat = skel.progs.tc_nat_wan_egress_v4;

    let mut ctx = TestSkb { ifindex, ..Default::default() };

    let mut packet_out = vec![0u8; payload.len()];
    let input = ProgramInput {
        data_in: Some(&payload),
        context_in: Some(ctx.as_mut_bytes()),
        context_out: None,
        data_out: Some(&mut packet_out),
        ..Default::default()
    };
    let result = egress_nat.test_run(input).expect("test_run failed");

    println!("return_value = {}", result.return_value as i32);
    println!("duration = {:?}", result.duration);
    println!("packet_out = {:?}", packet_out);
    crate::tests::helper::check::analyze(&packet_out);
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn tcp_syn_smoke_v4() {
        run_ipv4_egress_smoke(capture_ipv4_tcp_syn());
    }
}
