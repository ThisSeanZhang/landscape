use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use etherparse::{PacketBuilder, PacketHeaders};
use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    maps::{nat::StaticNatMappingV6Item, wan::add_wan_ip},
    maps::{Nat6TimerKey, Nat6TimerValue},
    stages::nat::tc_nat_skel::TcNatSkelBuilder,
    tests::TestSkb,
};

const IFINDEX: u32 = 6;
const PREFIX60_WAN_NPT_PREFIX: [u8; 8] = [0x24, 0x09, 0x88, 0x88, 0x66, 0x66, 0x4f, 0x25];

fn wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::100").unwrap()
}

fn local_target() -> Ipv6Addr {
    Ipv6Addr::from_str("::cafe").unwrap()
}

fn local_wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::cafe").unwrap()
}

fn remote() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
}

fn npt_id_mask(prefix_len: u8) -> u8 {
    if prefix_len >= 64 {
        0
    } else {
        ((1u16 << (64 - prefix_len)) - 1) as u8
    }
}

fn egress_ct6_key(src: Ipv6Addr, src_port: u16, l4proto: u8, prefix_len: u8) -> Nat6TimerKey {
    let bytes = src.octets();
    let mut suffix = [0u8; 8];
    suffix.copy_from_slice(&bytes[8..]);
    Nat6TimerKey {
        client_suffix: suffix,
        client_port: src_port.to_be(),
        id_byte: bytes[7] & npt_id_mask(prefix_len),
        l4_protocol: l4proto,
    }
}

fn ingress_ct6_key(dst: Ipv6Addr, dst_port: u16, l4proto: u8, prefix_len: u8) -> Nat6TimerKey {
    let bytes = dst.octets();
    let mut suffix = [0u8; 8];
    suffix.copy_from_slice(&bytes[8..]);
    Nat6TimerKey {
        client_suffix: suffix,
        client_port: dst_port.to_be(),
        id_byte: bytes[7] & npt_id_mask(prefix_len),
        l4_protocol: l4proto,
    }
}

fn lookup_ct6<T: MapCore>(map: &T, key: &Nat6TimerKey) -> Option<Nat6TimerValue> {
    let raw = map.lookup(key.as_bytes(), MapFlags::ANY).ok()??;
    Nat6TimerValue::read_from_bytes(&raw).ok()
}

fn build_ipv6_udp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .udp(src_port, dst_port);

    let payload = [0u8; 8];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::nat::add_static_nat6_mapping;

    const LAN_CLIENT_SUFFIX: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    const LAN_CLIENT_PREFIX: [u8; 8] = [0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0xab, 0xc5];

    #[test]
    fn udp_egress_creates_ct_with_is_static_one() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-static-ct-create");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 80, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        // No pre-populated CT entry — create path should be exercised.

        let pkt = build_ipv6_udp(lan_host(), remote(), 80, 9999);
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_egress.test_run(input).expect("test_run failed");
        assert_eq!(result.return_value as i32, -1, "egress should return TC_ACT_UNSPEC(-1)");

        // NPTv6 prefix translation
        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let src: Ipv6Addr = ipv6.source.into();
            assert_eq!(
                &src.octets()[..8],
                &PREFIX60_WAN_NPT_PREFIX,
                "src prefix should be NPT-translated to WAN prefix",
            );
            assert_eq!(&src.octets()[8..], &LAN_CLIENT_SUFFIX, "src suffix should be preserved",);
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.source_port, 80, "src_port should be unchanged");
        } else {
            panic!("expected UDP transport header in output");
        }

        // Verify CT was created with is_static=1
        let ct_key = egress_ct6_key(lan_host(), 80, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key)
            .expect("CT entry should have been created for egress");
        assert_eq!(ct_value.is_static, 1, "is_static should be 1 for static-backed CT");
        assert_eq!(ct_value.need_prefix_replace, 1);
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_EGRESS, "gress should be EGRESS");
    }

    #[test]
    fn udp_ingress_creates_ct_with_is_static_one() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-static-ct-create");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 80, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        // No pre-populated CT.

        let wan_npt_ip = Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap();
        let pkt = build_ipv6_udp(remote(), wan_npt_ip, 9999, 80);
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_ingress.test_run(input).expect("test_run failed");
        assert_eq!(result.return_value as i32, 0, "ingress should return TC_ACT_OK(0)");

        // NPTv6 dst rewrite
        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(
                &dst.octets()[..8],
                &LAN_CLIENT_PREFIX,
                "dst prefix should be rewritten to LAN client prefix",
            );
            assert_eq!(&dst.octets()[8..], &LAN_CLIENT_SUFFIX, "dst suffix should be preserved",);
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.destination_port, 80, "dst_port should be unchanged");
        } else {
            panic!("expected UDP transport header in output");
        }

        // Verify CT was created with is_static=1 (keyed by WAN destination)
        let ct_key = ingress_ct6_key(wan_npt_ip, 80, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key)
            .expect("CT entry should have been created for ingress");
        assert_eq!(ct_value.is_static, 1, "is_static should be 1 for static-backed ingress CT");
        assert_eq!(ct_value.need_prefix_replace, 1);
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_INGRESS, "gress should be INGRESS",);
    }

    #[test]
    fn udp_egress_ct_from_port_zero_static() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-port-zero-ct-create");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 0, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        let pkt = build_ipv6_udp(lan_host(), remote(), 443, 9999);
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_egress.test_run(input).expect("test_run failed");
        assert_eq!(result.return_value as i32, -1, "egress should return TC_ACT_UNSPEC(-1)");

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let src: Ipv6Addr = ipv6.source.into();
            assert_eq!(
                &src.octets()[..8],
                &PREFIX60_WAN_NPT_PREFIX,
                "src prefix should be NPT-translated to WAN prefix",
            );
            assert_eq!(&src.octets()[8..], &LAN_CLIENT_SUFFIX, "src suffix should be preserved",);
        } else {
            panic!("expected IPv6 header in output");
        }

        let ct_key = egress_ct6_key(lan_host(), 443, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key)
            .expect("CT entry should have been created for egress with port=0 static");
        assert_eq!(ct_value.is_static, 1, "is_static should be 1 for port=0 static-backed CT");
        assert_eq!(ct_value.need_prefix_replace, 1);
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_EGRESS, "gress should be EGRESS");
    }

    #[test]
    fn udp_ingress_ct_from_port_zero_static() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-port-zero-ct-create");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );

        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 0, lan_ip: lan_host(), l4_protocol: 17 }],
        );

        let wan_npt_ip = Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap();
        let pkt = build_ipv6_udp(remote(), wan_npt_ip, 9999, 443);
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_ingress.test_run(input).expect("test_run failed");
        assert_eq!(result.return_value as i32, 0, "ingress should return TC_ACT_OK(0)");

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(
                &dst.octets()[..8],
                &LAN_CLIENT_PREFIX,
                "dst prefix should be rewritten to LAN client prefix",
            );
            assert_eq!(&dst.octets()[8..], &LAN_CLIENT_SUFFIX, "dst suffix should be preserved",);
        } else {
            panic!("expected IPv6 header in output");
        }

        let ct_key = ingress_ct6_key(wan_npt_ip, 443, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key)
            .expect("CT entry should have been created for ingress with port=0 static");
        assert_eq!(
            ct_value.is_static, 1,
            "is_static should be 1 for port=0 static-backed ingress CT"
        );
        assert_eq!(ct_value.need_prefix_replace, 1);
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_INGRESS, "gress should be INGRESS");
    }

    #[test]
    fn udp_egress_zero_prefix_static_creates_pass_ct() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-zero-prefix-egress");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );
        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 53, lan_ip: local_target(), l4_protocol: 17 }],
        );

        for _ in 0..2 {
            let pkt = build_ipv6_udp(local_wan_ip(), remote(), 53, 9999);
            let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
            let mut packet_out = vec![0u8; pkt.len()];
            let result = skel
                .progs
                .tc_nat_wan_egress
                .test_run(ProgramInput {
                    data_in: Some(&pkt),
                    context_in: Some(ctx.as_mut_bytes()),
                    data_out: Some(&mut packet_out),
                    ..Default::default()
                })
                .expect("test_run failed");
            assert_eq!(result.return_value as i32, -1);

            let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
            let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net else {
                panic!("expected IPv6 header in output");
            };
            assert_eq!(Ipv6Addr::from(ipv6.source), local_wan_ip());
        }

        let ct_key = egress_ct6_key(local_wan_ip(), 53, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key).expect("missing egress CT");
        assert_eq!(ct_value.is_static, 1);
        assert_eq!(ct_value.need_prefix_replace, 0);
        assert_eq!(&ct_value.client_prefix, &local_wan_ip().octets()[..8]);
    }

    #[test]
    fn udp_ingress_zero_prefix_static_creates_pass_ct() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-zero-prefix-ingress");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V6(wan_ip()),
            None,
            60,
            Some(MacAddr::broadcast()),
        );
        add_static_nat6_mapping(
            &skel.maps.nat6_static_map,
            vec![StaticNatMappingV6Item { port: 53, lan_ip: local_target(), l4_protocol: 17 }],
        );

        for _ in 0..2 {
            let pkt = build_ipv6_udp(remote(), local_wan_ip(), 9999, 53);
            let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
            let mut packet_out = vec![0u8; pkt.len()];
            let result = skel
                .progs
                .tc_nat_wan_ingress
                .test_run(ProgramInput {
                    data_in: Some(&pkt),
                    context_in: Some(ctx.as_mut_bytes()),
                    data_out: Some(&mut packet_out),
                    ..Default::default()
                })
                .expect("test_run failed");
            assert_eq!(result.return_value as i32, 0);

            let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
            let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net else {
                panic!("expected IPv6 header in output");
            };
            assert_eq!(Ipv6Addr::from(ipv6.destination), local_wan_ip());
        }

        let ct_key = ingress_ct6_key(local_wan_ip(), 53, 17, 60);
        let ct_value = lookup_ct6(&skel.maps.nat6_timer_map, &ct_key).expect("missing ingress CT");
        assert_eq!(ct_value.is_static, 1);
        assert_eq!(ct_value.need_prefix_replace, 0);
        assert_eq!(&ct_value.client_prefix, &local_wan_ip().octets()[..8]);
    }
}
