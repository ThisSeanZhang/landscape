use std::{mem::MaybeUninit, net::Ipv6Addr};

use etherparse::{
    Ethernet2Header, IpFragOffset, Ipv6FragmentHeader, Ipv6Header, PacketBuilder, UdpHeader,
    ip_number,
};
use libbpf_rs::{
    ProgramInput, ProgramMut, ProgramType,
    skel::{OpenSkel, SkelBuilder as _},
};

use super::static_nat_xdp::XDP_PIPE_META_LEN;
use crate::{
    maps::nat::{StaticNatMappingV6Item, add_static_nat6_mapping},
    skel::{
        tc_nat6::{TcNat6Skel, TcNat6SkelBuilder},
        xdp_nat6::{XdpNat6Skel, XdpNat6SkelBuilder},
    },
    tests::{isolated_pin_root, pkt::simple_ipv6_udp},
};

const WAN_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0x20, 0, 0, 0, 0);
const WAN_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0x25, 0, 0, 0, 0x100);
const LAN_CLIENT: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 5, 0, 0, 0, 0x100);
const REMOTE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 9);
const TC_ACT_OK: i32 = 0;
const TC_ACT_UNSPEC: i32 = -1;
const XDP_PASS: i32 = 2;

fn with_nat6(test: impl FnOnce(&TcNat6Skel<'_>, &XdpNat6Skel<'_>)) {
    let root = isolated_pin_root("nat6-checksums");
    let prefix = crate::stages::nat6::wan_ro_prefix6(Some(WAN_PREFIX));
    let mask = crate::maps::wan::compute_npt_mask(60);
    let mut tc_obj = MaybeUninit::uninit();
    let mut builder = TcNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut tc = builder.open(&mut tc_obj).unwrap();
    let rodata = tc.maps.rodata_data.as_deref_mut().unwrap();
    rodata.wan_ro_prefix6.b = prefix;
    rodata.wan_ro_npt_mask = mask;
    let tc = tc.load().unwrap();

    let mut xdp_obj = MaybeUninit::uninit();
    let mut builder = XdpNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut xdp = builder.open(&mut xdp_obj).unwrap();
    let rodata = xdp.maps.rodata_data.as_deref_mut().unwrap();
    rodata.wan_ro_prefix6.b = prefix;
    rodata.wan_ro_npt_mask = mask;
    let xdp = xdp.load().unwrap();
    test(&tc, &xdp);
}

// Return the first and later fragments, plus the same datagram in one atomic fragment.
fn udp_fragments(src: Ipv6Addr, dst: Ipv6Addr, id: u32) -> [Vec<u8>; 3] {
    let packet = simple_ipv6_udp(src, dst);
    let (eth, ip_packet) = Ethernet2Header::from_slice(&packet).unwrap();
    let (mut ip, udp) = Ipv6Header::from_slice(ip_packet).unwrap();
    ip.next_header = ip_number::IPV6_FRAGMENTATION_HEADER;
    let (header, payload) = udp.split_at(UdpHeader::LEN);
    [(0, true, header), (1, false, payload), (0, false, udp)].map(|(offset, more, bytes)| {
        let frag = Ipv6FragmentHeader::new(
            ip_number::UDP,
            IpFragOffset::try_new(offset).unwrap(),
            more,
            id,
        );
        ip.set_payload_length(Ipv6FragmentHeader::LEN + bytes.len()).unwrap();
        let mut frame = eth.to_bytes().to_vec();
        ip.write(&mut frame).unwrap();
        frag.write(&mut frame).unwrap();
        frame.extend_from_slice(bytes);
        frame
    })
}

#[track_caller]
fn run(prog: &ProgramMut<'_>, frame: &[u8], verdict: i32, flags: u32) -> Vec<u8> {
    let mut out = vec![0; frame.len() + XDP_PIPE_META_LEN];
    let result = prog
        .test_run(ProgramInput {
            data_in: Some(frame),
            data_out: Some(&mut out),
            flags,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.return_value as i32, verdict, "{:?} verdict", prog.name());
    let data = result.data.unwrap();
    if data.len() == frame.len() + XDP_PIPE_META_LEN {
        data[XDP_PIPE_META_LEN..].to_vec()
    } else {
        assert_eq!(data.len(), frame.len(), "unexpected frame length");
        data.to_vec()
    }
}

fn map_udp53(tc: &TcNat6Skel<'_>, target: Ipv6Addr) {
    add_static_nat6_mapping(
        &tc.maps.nat6_static_map,
        [StaticNatMappingV6Item {
            port: 53,
            lan_ip: target,
            l4_protocol: ip_number::UDP.0,
        }],
    );
}

fn udp_with_computed_zero(
    before: (Ipv6Addr, Ipv6Addr),
    after: (Ipv6Addr, Ipv6Addr),
) -> (Vec<u8>, Vec<u8>) {
    let frame = |(src, dst): (Ipv6Addr, Ipv6Addr), word: u16| {
        let mut packet = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv6(src.octets(), dst.octets(), 64)
            .udp(10000, 53)
            .write(&mut packet, &word.to_be_bytes())
            .unwrap();
        packet
    };
    let checksum = |frame: &[u8]| {
        UdpHeader::from_slice(&frame[Ethernet2Header::LEN + Ipv6Header::LEN..]).unwrap().0.checksum
    };
    // Adding the original checksum as a payload word makes the translated sum all ones.
    let word = checksum(&frame(after, 0));
    let input = frame(before, word);
    let expected = frame(after, word);
    assert_ne!(checksum(&input), 0xffff);
    assert_eq!(checksum(&expected), 0xffff);
    (input, expected)
}

fn assert_udp_translation(
    prog: &ProgramMut<'_>,
    verdict: i32,
    before: (Ipv6Addr, Ipv6Addr),
    after: (Ipv6Addr, Ipv6Addr),
) {
    let [first, later, atomic] = udp_fragments(before.0, before.1, 7);
    let [expected_first, expected_later, expected_atomic] = udp_fragments(after.0, after.1, 7);
    let unfragmented = simple_ipv6_udp(before.0, before.1);
    let expected_unfragmented = simple_ipv6_udp(after.0, after.1);
    let (zero, expected_zero) = udp_with_computed_zero(before, after);
    // In COMPLETE mode the kernel also checks skb->csum against each output frame.
    let flags: &[u32] = match prog.prog_type() {
        ProgramType::SchedCls => &[0, libbpf_sys::BPF_F_TEST_SKB_CHECKSUM_COMPLETE],
        _ => &[0],
    };
    for &flag in flags {
        for (kind, input, expected) in [
            ("first", &first, &expected_first),
            ("later", &later, &expected_later),
            ("atomic", &atomic, &expected_atomic),
            ("unfragmented", &unfragmented, &expected_unfragmented),
            ("computed zero", &zero, &expected_zero),
        ] {
            assert_eq!(&run(prog, input, verdict, flag), expected, "{kind}, flags={flag}");
        }
    }
}

#[test]
fn tc_egress_udp_checksums() {
    with_nat6(|tc, _| {
        assert_udp_translation(
            &tc.progs.tc_nat_wan_egress_v6,
            TC_ACT_UNSPEC,
            (LAN_CLIENT, REMOTE),
            (WAN_CLIENT, REMOTE),
        )
    });
}

#[test]
fn xdp_egress_udp_checksums() {
    with_nat6(|_, xdp| {
        assert_udp_translation(
            &xdp.progs.egress_nat_v6,
            XDP_PASS,
            (LAN_CLIENT, REMOTE),
            (WAN_CLIENT, REMOTE),
        )
    });
}

#[test]
fn tc_ingress_udp_checksums() {
    with_nat6(|tc, _| {
        map_udp53(tc, LAN_CLIENT);
        assert_udp_translation(
            &tc.progs.tc_nat_wan_ingress_v6,
            TC_ACT_OK,
            (REMOTE, WAN_CLIENT),
            (REMOTE, LAN_CLIENT),
        );
    });
}

#[test]
fn xdp_ingress_udp_checksums() {
    with_nat6(|tc, xdp| {
        map_udp53(tc, LAN_CLIENT);
        assert_udp_translation(
            &xdp.progs.ingress_nat_v6,
            XDP_PASS,
            (REMOTE, WAN_CLIENT),
            (REMOTE, LAN_CLIENT),
        );
    });
}
