use std::{mem::MaybeUninit, net::Ipv6Addr, os::fd::AsFd};

use etherparse::{
    Ethernet2Header, IcmpEchoHeader, Icmpv6Type, IpFragOffset, IpHeaders, Ipv6Extensions,
    Ipv6FragmentHeader, Ipv6Header, Ipv6RawExtHeader, PacketBuilder, UdpHeader, icmpv6, ip_number,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut, ProgramType,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, IntoBytes};

mod tap;

use super::static_nat_xdp::XDP_PIPE_META_LEN;
use crate::{
    maps::{
        Nat6TimerKey, Nat6TimerValue,
        nat::{StaticNatMappingV6Item, add_static_nat6_mapping},
    },
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
const ROUTER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 1);
const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

fn with_nat6(test: impl FnOnce(&TcNat6Skel<'_>, &XdpNat6Skel<'_>)) {
    with_nat6_config(60, Ethernet2Header::LEN, test);
}

fn with_nat6_config(
    prefix_len: u8,
    l3_offset: usize,
    test: impl FnOnce(&TcNat6Skel<'_>, &XdpNat6Skel<'_>),
) {
    let root = isolated_pin_root("nat6-checksums");
    let prefix = crate::stages::nat6::wan_ro_prefix6(Some(WAN_PREFIX));
    let mask = crate::maps::wan::compute_npt_mask(prefix_len);
    let mut tc_obj = MaybeUninit::uninit();
    let mut builder = TcNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut tc = builder.open(&mut tc_obj).unwrap();
    let rodata = tc.maps.rodata_data.as_deref_mut().unwrap();
    rodata.wan_ro_prefix6.b = prefix;
    rodata.wan_ro_npt_mask = mask;
    rodata.current_l3_offset = l3_offset as u32;
    let tc = tc.load().unwrap();

    let mut xdp_obj = MaybeUninit::uninit();
    let mut builder = XdpNat6SkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&root).unwrap();
    let mut xdp = builder.open(&mut xdp_obj).unwrap();
    xdp.maps.nat6_mapping_map.reuse_fd(tc.maps.nat6_mapping_map.as_fd()).unwrap();
    xdp.maps.nat6_timer_map.reuse_fd(tc.maps.nat6_timer_map.as_fd()).unwrap();
    xdp.maps.frag6_cache_lan.reuse_fd(tc.maps.frag6_cache_lan.as_fd()).unwrap();
    xdp.maps.frag6_cache_wan.reuse_fd(tc.maps.frag6_cache_wan.as_fd()).unwrap();
    let rodata = xdp.maps.rodata_data.as_deref_mut().unwrap();
    rodata.wan_ro_prefix6.b = prefix;
    rodata.wan_ro_npt_mask = mask;
    rodata.current_l3_offset = l3_offset as u32;
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

fn checksum_test_flags(prog: &ProgramMut<'_>) -> &'static [u32] {
    // In COMPLETE mode the kernel also checks skb->csum against the output frame.
    match prog.prog_type() {
        ProgramType::SchedCls => &[0, libbpf_sys::BPF_F_TEST_SKB_CHECKSUM_COMPLETE],
        _ => &[0],
    }
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
    for &flag in checksum_test_flags(prog) {
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

#[test]
fn static_ingress_fragments_stay_in_their_wan_subnet_across_hooks() {
    with_nat6(|tc, xdp| {
        map_udp53(tc, LAN_CLIENT);
        let tc = (&tc.progs.tc_nat_wan_ingress_v6, TC_ACT_OK, TC_ACT_SHOT);
        let xdp = (&xdp.progs.ingress_nat_v6, XDP_PASS, XDP_DROP);
        let other_subnet = "2001:db8:1:26::100".parse().unwrap();
        for (first_hook, later_hook, id) in [(xdp, tc, 7), (tc, xdp, 8)] {
            let [first, later, _] = udp_fragments(REMOTE, WAN_CLIENT, id);
            let [expected_first, expected_later, _] = udp_fragments(REMOTE, LAN_CLIENT, id);
            let [_, other_later, _] = udp_fragments(REMOTE, other_subnet, id);
            assert_eq!(run(first_hook.0, &first, first_hook.1, 0), expected_first);
            run(later_hook.0, &other_later, later_hook.2, 0);
            assert_eq!(run(later_hook.0, &later, later_hook.1, 0), expected_later);
        }
    });
}

#[test]
fn prefix56_routes_interleaved_replies_to_clients_with_the_same_iid_and_port() {
    let clients = [
        (LAN_CLIENT, "2001:db8:1:5::100".parse().unwrap()),
        ("fd00:2:0:a5::100".parse().unwrap(), "2001:db8:1:a5::100".parse().unwrap()),
    ];
    let reply = |dst: Ipv6Addr| {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv6(REMOTE.octets(), dst.octets(), 64)
            .udp(53, 10000)
            .write(&mut frame, b"reply")
            .unwrap();
        frame
    };
    with_nat6_config(56, Ethernet2Header::LEN, |tc, xdp| {
        let egress =
            [(&tc.progs.tc_nat_wan_egress_v6, TC_ACT_UNSPEC), (&xdp.progs.egress_nat_v6, XDP_PASS)];
        for ((lan, wan), (prog, verdict)) in clients.into_iter().zip(egress) {
            assert_eq!(
                run(prog, &simple_ipv6_udp(lan, REMOTE), verdict, 0),
                simple_ipv6_udp(wan, REMOTE)
            );
        }
        assert_eq!(tc.maps.nat6_timer_map.keys().count(), 2);
        for (lan, wan) in clients.into_iter().rev() {
            for (prog, verdict) in [
                (&tc.progs.tc_nat_wan_ingress_v6, TC_ACT_OK),
                (&xdp.progs.ingress_nat_v6, XDP_PASS),
            ] {
                assert_eq!(run(prog, &reply(wan), verdict, 0), reply(lan));
            }
        }
    });
}

fn icmp6_error(src: Ipv6Addr, dst: Ipv6Addr, kind: Icmpv6Type, quote: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    PacketBuilder::ethernet2([2; 6], [4; 6])
        .ipv6(src.octets(), dst.octets(), 64)
        .icmpv6(kind)
        .write(&mut frame, quote)
        .unwrap();
    frame
}

#[test]
fn packet_too_big_quotes_echo_with_destination_options() {
    for l3_offset in [Ethernet2Header::LEN, 0] {
        let packet = |src: Ipv6Addr, dst: Ipv6Addr, kind, payload: &[u8]| {
            let ip = Ipv6Header {
                source: src.octets(),
                destination: dst.octets(),
                hop_limit: 64,
                ..Default::default()
            };
            let ext = Ipv6Extensions {
                destination_options: Some(
                    Ipv6RawExtHeader::new_raw(ip_number::IPV6_ICMP, &[0; 6]).unwrap(),
                ),
                ..Default::default()
            };
            let mut frame = Vec::new();
            PacketBuilder::ethernet2([2; 6], [4; 6])
                .ip(IpHeaders::Ipv6(ip, ext))
                .icmpv6(kind)
                .write(&mut frame, payload)
                .unwrap();
            frame[Ethernet2Header::LEN - l3_offset..].to_vec()
        };
        let echo = Icmpv6Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 7 });
        let lan = packet(LAN_CLIENT, REMOTE, echo.clone(), &[0x5a; 1461]);
        let wan = packet(WAN_CLIENT, REMOTE, echo, &[0x5a; 1461]);
        // Include the options header, the Echo header and one payload byte.
        let quote = l3_offset..l3_offset + Ipv6Header::LEN + 8 + 9;
        let ptb = Icmpv6Type::PacketTooBig { mtu: 1492 };
        let expected = packet(ROUTER, LAN_CLIENT, ptb.clone(), &lan[quote.clone()]);
        with_nat6_config(60, l3_offset, |tc, xdp| {
            for (egress, out, ingress, back) in [
                (
                    &tc.progs.tc_nat_wan_egress_v6,
                    TC_ACT_UNSPEC,
                    &tc.progs.tc_nat_wan_ingress_v6,
                    TC_ACT_OK,
                ),
                (&xdp.progs.egress_nat_v6, XDP_PASS, &xdp.progs.ingress_nat_v6, XDP_PASS),
            ] {
                let translated = run(egress, &lan, out, 0);
                assert_eq!(translated, wan);
                let error = packet(ROUTER, WAN_CLIENT, ptb.clone(), &translated[quote.clone()]);
                for &flag in checksum_test_flags(ingress) {
                    assert_eq!(run(ingress, &error, back, flag), expected);
                }
            }
        });
    }
}

#[test]
fn icmp6_error_matches_existing_dynamic_flow() {
    let tcp = |client: Ipv6Addr| {
        let from_client = |seq| {
            PacketBuilder::ethernet2([2; 6], [4; 6])
                .ipv6(client.octets(), REMOTE.octets(), 64)
                .tcp(12345, 443, seq, 4096)
        };
        let mut syn = Vec::new();
        from_client(100).syn().write(&mut syn, &[]).unwrap();
        let mut syn_ack = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv6(REMOTE.octets(), client.octets(), 64)
            .tcp(443, 12345, 200, 4096)
            .syn()
            .ack(101)
            .write(&mut syn_ack, &[])
            .unwrap();
        let mut ack = Vec::new();
        from_client(101).ack(201).write(&mut ack, &[]).unwrap();
        let mut data = Vec::new();
        from_client(101).ack(201).write(&mut data, &[0x55; 1400]).unwrap();
        [syn, syn_ack, ack, data]
    };
    for create_in_xdp in [false, true] {
        with_nat6(|tc, xdp| {
            let (egress, verdict, ingress, back) = if create_in_xdp {
                (&xdp.progs.egress_nat_v6, XDP_PASS, &xdp.progs.ingress_nat_v6, XDP_PASS)
            } else {
                (
                    &tc.progs.tc_nat_wan_egress_v6,
                    TC_ACT_UNSPEC,
                    &tc.progs.tc_nat_wan_ingress_v6,
                    TC_ACT_OK,
                )
            };
            let [lan_syn, lan_syn_ack, lan_ack, lan_data] = tcp(LAN_CLIENT);
            let [wan_syn, wan_syn_ack, wan_ack, wan_data] = tcp(WAN_CLIENT);
            assert_eq!(run(egress, &lan_syn, verdict, 0), wan_syn);
            assert_eq!(run(ingress, &wan_syn_ack, back, 0), lan_syn_ack);
            assert_eq!(run(egress, &lan_ack, verdict, 0), wan_ack);
            // The UDP checksum after translating the quote back to the LAN is 0xffff.
            let (wan_udp, lan_udp) =
                udp_with_computed_zero((WAN_CLIENT, REMOTE), (LAN_CLIENT, REMOTE));
            for (proto, lan, wan, error) in [
                (ip_number::TCP, lan_data, wan_data, Icmpv6Type::PacketTooBig { mtu: 1280 }),
                (
                    ip_number::UDP,
                    lan_udp,
                    wan_udp,
                    Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::NoRoute),
                ),
            ] {
                let wire = run(egress, &lan, verdict, 0);
                assert_eq!(wire, wan);
                let ct = &tc.maps.nat6_timer_map;
                let key = ct
                    .keys()
                    .find(|bytes| {
                        Nat6TimerKey::read_from_bytes(bytes).unwrap().local.l4_protocol == proto.0
                    })
                    .expect("outbound traffic must create the flow");
                let entry = || {
                    Nat6TimerValue::read_from_bytes(
                        &ct.lookup(&key, MapFlags::ANY).unwrap().unwrap(),
                    )
                    .unwrap()
                };
                let before = entry();
                let flow_count = ct.keys().count();
                assert_eq!((before.is_static, before.allow_reuse), (0, 0));
                let wire_ip = &wire[Ethernet2Header::LEN..];
                let lan_ip = &lan[Ethernet2Header::LEN..];
                for len in [Ipv6Header::LEN + 8, wire_ip.len().min(1232)] {
                    let input = icmp6_error(ROUTER, WAN_CLIENT, error.clone(), &wire_ip[..len]);
                    let expected = icmp6_error(ROUTER, LAN_CLIENT, error.clone(), &lan_ip[..len]);
                    for (ingress, verdict) in [
                        (&tc.progs.tc_nat_wan_ingress_v6, TC_ACT_OK),
                        (&xdp.progs.ingress_nat_v6, XDP_PASS),
                    ] {
                        for &flag in checksum_test_flags(ingress) {
                            assert_eq!(
                                run(ingress, &input, verdict, flag),
                                expected,
                                "{proto:?}, {len} quoted bytes, {:?}",
                                ingress.name()
                            );
                        }
                    }
                }
                let after = entry();
                assert_eq!(after.create_time, before.create_time);
                assert_eq!(after.tcp_flags, before.tcp_flags);
                assert_eq!(
                    (after.ingress_packets, after.egress_packets),
                    (before.ingress_packets, before.egress_packets)
                );
                assert_eq!(ct.keys().count(), flow_count);
                assert_eq!(run(egress, &lan, verdict, 0), wan, "data after the ICMPv6 error");
            }
        });
    }
}

#[test]
fn icmp6_error_without_matching_dynamic_flow_is_dropped() {
    with_nat6(|tc, xdp| {
        let udp = |client: Ipv6Addr, peer: Ipv6Addr, port: u16| {
            let mut frame = Vec::new();
            PacketBuilder::ethernet2([2; 6], [4; 6])
                .ipv6(client.octets(), peer.octets(), 64)
                .udp(10000, port)
                .write(&mut frame, &[])
                .unwrap();
            frame
        };
        let reject = |wan: &[u8]| {
            let kind = Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::NoRoute);
            let error = icmp6_error(ROUTER, WAN_CLIENT, kind, &wan[Ethernet2Header::LEN..]);
            run(&tc.progs.tc_nat_wan_ingress_v6, &error, TC_ACT_SHOT, 0);
            run(&xdp.progs.ingress_nat_v6, &error, XDP_DROP, 0);
        };
        let wan = udp(WAN_CLIENT, REMOTE, 53);
        let ct = &tc.maps.nat6_timer_map;
        reject(&wan);
        assert_eq!(ct.keys().count(), 0, "an ICMPv6 error cannot create a flow");

        add_static_nat6_mapping(
            &tc.maps.nat6_static_map,
            [StaticNatMappingV6Item {
                port: 10000,
                lan_ip: LAN_CLIENT,
                l4_protocol: ip_number::TCP.0,
            }],
        );
        reject(&wan); // The quoted UDP port has a static rule for TCP only.
        assert_eq!(ct.keys().count(), 0);

        let lan = udp(LAN_CLIENT, REMOTE, 53);
        assert_eq!(run(&tc.progs.tc_nat_wan_egress_v6, &lan, TC_ACT_UNSPEC, 0), wan);
        let key = ct.keys().next().expect("outgoing UDP must create the flow");
        let before = ct.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        reject(&udp(WAN_CLIENT, ROUTER, 53));
        reject(&udp(WAN_CLIENT, REMOTE, 54));
        assert_eq!(ct.keys().count(), 1);
        assert_eq!(ct.lookup(&key, MapFlags::ANY).unwrap().unwrap(), before);
    });
}

#[test]
fn icmp6_short_tcp_quote() {
    with_nat6(|tc, xdp| {
        add_static_nat6_mapping(
            &tc.maps.nat6_static_map,
            [StaticNatMappingV6Item {
                port: 443,
                lan_ip: LAN_CLIENT,
                l4_protocol: ip_number::TCP.0,
            }],
        );
        let lan_router = "fd00:2:0:8::1".parse().unwrap();
        let translated_router = "2001:db8:1:28::1".parse().unwrap();
        for (
            programs,
            (outer_src, outer_dst),
            (new_src, new_dst),
            (quoted_dst, new_quoted_dst),
            ports,
        ) in [
            (
                [
                    (&tc.progs.tc_nat_wan_ingress_v6, TC_ACT_OK),
                    (&xdp.progs.ingress_nat_v6, XDP_PASS),
                ],
                (ROUTER, WAN_CLIENT),
                (ROUTER, LAN_CLIENT),
                (REMOTE, REMOTE),
                (443, 12345),
            ),
            (
                [
                    (&tc.progs.tc_nat_wan_egress_v6, TC_ACT_UNSPEC),
                    (&xdp.progs.egress_nat_v6, XDP_PASS),
                ],
                (lan_router, REMOTE),
                (translated_router, REMOTE),
                (LAN_CLIENT, WAN_CLIENT),
                (12345, 443),
            ),
        ] {
            let quoted_tcp = |src: Ipv6Addr, dst: Ipv6Addr| {
                let mut pkt = Vec::new();
                PacketBuilder::ipv6(src.octets(), dst.octets(), 64)
                    .tcp(ports.0, ports.1, 1234, 4096)
                    .write(&mut pkt, &[])
                    .unwrap();
                pkt
            };
            let original = quoted_tcp(outer_dst, quoted_dst);
            let translated = quoted_tcp(new_dst, new_quoted_dst);
            let check = |input: &[u8], expected: &[u8]| {
                for (prog, verdict) in programs {
                    for &flag in checksum_test_flags(prog) {
                        assert_eq!(
                            run(prog, input, verdict, flag),
                            expected,
                            "{:?}, flags={flag}",
                            prog.name()
                        );
                    }
                }
            };
            for (kind, tcp_bytes, link_padding) in [
                (Icmpv6Type::PacketTooBig { mtu: 1280 }, 8, 0),
                (Icmpv6Type::TimeExceeded(icmpv6::TimeExceededCode::HopLimitExceeded), 17, 0),
                (Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::NoRoute), 17, 8),
                (
                    Icmpv6Type::ParameterProblem(icmpv6::ParameterProblemHeader {
                        code: icmpv6::ParameterProblemCode::ErroneousHeaderField,
                        pointer: 6,
                    }),
                    18,
                    0,
                ),
            ] {
                let end = Ipv6Header::LEN + tcp_bytes;
                let mut quote = translated[..end].to_vec();
                if tcp_bytes < 18 {
                    quote[Ipv6Header::LEN..].copy_from_slice(&original[Ipv6Header::LEN..end]);
                }
                let mut input = icmp6_error(outer_src, outer_dst, kind.clone(), &original[..end]);
                let mut expected = icmp6_error(new_src, new_dst, kind, &quote);
                input.resize(input.len() + link_padding, 0xa5);
                expected.resize(expected.len() + link_padding, 0xa5);
                check(&input, &expected);
            }

            // The RFC 4884 extension starts where the quoted TCP checksum would be.
            let extended = |src: Ipv6Addr, dst: Ipv6Addr, inner: &[u8]| {
                let (mut ip, tcp) = Ipv6Header::from_slice(inner).unwrap();
                let opts = Ipv6RawExtHeader::new_raw(ip_number::TCP, &[0; 70]).unwrap();
                ip.next_header = ip_number::IPV6_DEST_OPTIONS;
                ip.set_payload_length(opts.header_len() + tcp.len()).unwrap();
                let mut payload = ip.to_bytes().to_vec();
                opts.write(&mut payload).unwrap();
                payload.extend_from_slice(&tcp[..16]);
                assert_eq!(payload.len(), 128);
                payload.extend_from_slice(&[0x20, 0, 0, 0, 0, 8, 1, 1, 0, 1, 1, 64]);
                let kind = Icmpv6Type::Unknown { type_u8: 3, code_u8: 0, bytes5to8: [16, 0, 0, 0] };
                icmp6_error(src, dst, kind, &payload)
            };
            check(
                &extended(outer_src, outer_dst, &original),
                &extended(new_src, new_dst, &translated),
            );
        }
    });
}

#[test]
fn exact_ct_then_static_then_shared_dynamic_mapping_across_hooks() {
    with_nat6(|tc, xdp| {
        let frame = |src: Ipv6Addr, dst: Ipv6Addr, port, reverse| {
            let (sport, dport) = if reverse { (port, 12345) } else { (12345, port) };
            let mut out = Vec::new();
            PacketBuilder::ethernet2([2; 6], [4; 6])
                .ipv6(src.octets(), dst.octets(), 64)
                .udp(sport, dport)
                .write(&mut out, &[])
                .unwrap();
            out
        };
        let a = frame(LAN_CLIENT, REMOTE, 53, false);
        let b = frame(LAN_CLIENT, ROUTER, 53, false);
        let mut ctx = crate::tests::TestSkb { mark: 0x8000, ..Default::default() };
        assert_eq!(
            tc.progs
                .tc_nat_wan_egress_v6
                .test_run(ProgramInput {
                    data_in: Some(&a),
                    context_in: Some(ctx.as_mut_bytes()),
                    ..Default::default()
                })
                .unwrap()
                .return_value as i32,
            TC_ACT_UNSPEC
        );
        // A new remote arriving in XDP needs the dynamic mapping created by TC.
        let response = frame(ROUTER, WAN_CLIENT, 53, true);
        assert_eq!(
            run(&xdp.progs.ingress_nat_v6, &response, XDP_PASS, 0),
            frame(ROUTER, LAN_CLIENT, 53, true)
        );
        assert_eq!(
            run(&tc.progs.tc_nat_wan_egress_v6, &b, TC_ACT_UNSPEC, 0),
            frame(WAN_CLIENT, ROUTER, 53, false)
        );

        // Wildcard translates; the exact static rule passes the same local endpoint through.
        add_static_nat6_mapping(
            &tc.maps.nat6_static_map,
            [
                StaticNatMappingV6Item { port: 0, lan_ip: LAN_CLIENT, l4_protocol: 17 },
                StaticNatMappingV6Item {
                    port: 12345,
                    lan_ip: "::100".parse().unwrap(),
                    l4_protocol: 17,
                },
            ],
        );
        let c = frame(LAN_CLIENT, ROUTER, 54, false);
        assert_eq!(run(&xdp.progs.egress_nat_v6, &c, XDP_PASS, 0), c);
        assert_eq!(
            run(&xdp.progs.egress_nat_v6, &b, XDP_PASS, 0),
            frame(WAN_CLIENT, ROUTER, 53, false)
        );
        let incoming = frame(REMOTE, WAN_CLIENT, 55, true);
        assert_eq!(run(&tc.progs.tc_nat_wan_ingress_v6, &incoming, TC_ACT_OK, 0), incoming);
        assert_eq!(tc.maps.nat6_timer_map.keys().count(), 4);
        let mappings = &tc.maps.nat6_mapping_map;
        let keys: Vec<_> = mappings.keys().collect();
        assert_eq!(keys.len(), 1);
        let mapping = crate::maps::Nat6MappingValue::read_from_bytes(
            &mappings.lookup(&keys[0], MapFlags::ANY).unwrap().unwrap(),
        )
        .unwrap();
        assert_eq!(mapping.refs, 2);
    });
}
