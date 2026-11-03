//! Host probes must bypass Flow selection without bypassing NAT connection state.
//! Exercise the production WAN entry tail-calling the real NAT stage, then its reply.
use super::common::*;
use crate::{
    skel::{tc_nat6::TcNat6SkelBuilder, tc_wan_egress_route::TcWanEgressRouteSkelBuilder},
    tests::{TestSkb, isolated_pin_root},
};
use etherparse::PacketBuilder;
use landscape_common::flow::mark::{MarkType, SocketMark};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};
use std::{
    mem::MaybeUninit,
    net::Ipv6Addr,
    os::fd::{AsFd, AsRawFd},
};
use zerocopy::IntoBytes;

const CHAIN: u16 = 7;
fn run_marked(prog: &ProgramMut<'_>, packet: &[u8], mark: u32) -> (i32, Vec<u8>) {
    let mut ctx = TestSkb { ifindex: 1, mark, ..Default::default() };
    let mut out = vec![0; packet.len()];
    let result = prog
        .test_run(ProgramInput {
            data_in: Some(packet),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .unwrap();
    (result.return_value as i32, out)
}
fn routed(nat: &ProgramMut<'_>, packet: &[u8], probe: bool) -> (i32, Vec<u8>) {
    let pin = isolated_pin_root("host-probe-route");
    let mut builder = TcWanEgressRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut obj = MaybeUninit::uninit();
    let route = builder.open(&mut obj).unwrap().load().unwrap();
    route
        .maps
        .tc_wan_egress_roots
        .update(
            &u32::from(CHAIN).to_ne_bytes(),
            &nat.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )
        .unwrap();
    // No default Flow slots: success requires the explicit WAN chain.
    let kind = if probe {
        MarkType::HostProbe { chain_id: CHAIN }
    } else {
        MarkType::HostDirect { chain_id: CHAIN }
    };
    run_marked(&route.progs.tc_wan_egress_route, packet, SocketMark::new(kind, 0).into())
}

#[test]
fn host_probe_ipv4_dns_retains_nat_state_and_accepts_reply() {
    for probe in [false, true] {
        with_skel(&[40000], &[], &[], |nat| {
            let outgoing = udp_pkt(WAN_IP, REMOTE_IP, 54321, 53);
            let (ret, out) = routed(&nat.progs.tc_v4_from_lan, &outgoing, probe);
            assert_eq!(ret, -1);
            let port = u16::from_be_bytes(out[34..36].try_into().unwrap());
            assert_eq!(port, if probe { 40000 } else { 54321 });
            let reply = udp_pkt(REMOTE_IP, WAN_IP, 53, port);
            let (ret, restored) = run_marked(&nat.progs.tc_v4_from_wan, &reply, 0);
            assert_eq!(ret, if probe { 0 } else { 2 }, "probe={probe}");
            if probe {
                assert_eq!(parse_ipv4_dst(&restored), WAN_IP);
                assert_eq!(u16::from_be_bytes(restored[36..38].try_into().unwrap()), 54321);
            }
        });
    }
}

fn udp6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv6(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let mut packet = Vec::new();
    builder.write(&mut packet, &[0; 12]).unwrap();
    packet
}
#[test]
fn host_probe_ipv6_dns_retains_nat_state_and_accepts_reply() {
    for probe in [false, true] {
        let pin = isolated_pin_root("host-probe-nat6");
        let mut builder = TcNat6SkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin).unwrap();
        let mut obj = MaybeUninit::uninit();
        let mut open = builder.open(&mut obj).unwrap();
        let src: Ipv6Addr = "2001:db8:1::1234".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8:2::53".parse().unwrap();
        let ro = open.maps.rodata_data.as_deref_mut().unwrap();
        ro.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(src));
        ro.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(64);
        let nat = open.load().unwrap();
        let (ret, _) = routed(&nat.progs.tc_nat_wan_egress_v6, &udp6(src, dst, 54321, 53), probe);
        assert_eq!(ret, -1);
        let (ret, _) = run_marked(&nat.progs.tc_nat_wan_ingress_v6, &udp6(dst, src, 53, 54321), 0);
        assert_eq!(ret, if probe { 0 } else { 2 }, "probe={probe}");
    }
}

#[test]
fn host_probe_missing_chain_never_falls_back_to_kernel_exit() {
    let pin = isolated_pin_root("host-probe-missing");
    let mut builder = TcWanEgressRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut obj = MaybeUninit::uninit();
    let route = builder.open(&mut obj).unwrap().load().unwrap();
    let pkt = udp_pkt(WAN_IP, REMOTE_IP, 54321, 53);
    let mark = SocketMark::new(MarkType::HostProbe { chain_id: CHAIN }, 0).into();
    assert_eq!(run_marked(&route.progs.tc_wan_egress_route, &pkt, mark).0, 2);
}
