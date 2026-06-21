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
use zerocopy::IntoBytes;

use crate::{
    map_setting::{add_wan_ip, nat::StaticNatMappingV6Item},
    stages::nat::tc_nat_skel::{types, TcNatSkelBuilder},
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

fn egress_ct6_key(
    src: Ipv6Addr,
    src_port: u16,
    l4proto: u8,
    prefix_len: u8,
) -> types::nat_timer_key_v6 {
    let bytes = src.octets();
    let mut suffix = [0u8; 8];
    suffix.copy_from_slice(&bytes[8..]);
    types::nat_timer_key_v6 {
        client_suffix: suffix,
        client_port: src_port.to_be(),
        id_byte: bytes[7] & npt_id_mask(prefix_len),
        l4_protocol: l4proto,
    }
}

fn ingress_ct6_key(
    dst: Ipv6Addr,
    dst_port: u16,
    l4proto: u8,
    prefix_len: u8,
) -> types::nat_timer_key_v6 {
    let bytes = dst.octets();
    let mut suffix = [0u8; 8];
    suffix.copy_from_slice(&bytes[8..]);
    types::nat_timer_key_v6 {
        client_suffix: suffix,
        client_port: dst_port.to_be(),
        id_byte: bytes[7] & npt_id_mask(prefix_len),
        l4_protocol: l4proto,
    }
}

fn lookup_ct6<T: MapCore>(
    map: &T,
    key: &types::nat_timer_key_v6,
) -> Option<types::nat_timer_value_v6> {
    let raw = map.lookup(unsafe { plain::as_bytes(key) }, MapFlags::ANY).ok()??;
    Some(unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<types::nat_timer_value_v6>()) })
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
    use crate::map_setting::nat::add_static_nat6_mapping;

    const LAN_CLIENT_SUFFIX: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    const LAN_CLIENT_PREFIX: [u8; 8] = [0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0xab, 0xc5];

    #[test]
    fn udp_egress_creates_ct_with_is_static_one() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-ct-create");
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
            &skel.maps.nat6_static_mappings,
            vec![StaticNatMappingV6Item {
                wan_port: 80,
                lan_port: 80,
                lan_ip: lan_host(),
                l4_protocol: 17, // UDP
            }],
        );

        // No pre-populated CT entry — create path should be exercised.

        let mut pkt = build_ipv6_udp(lan_host(), remote(), 80, 9999);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&mut pkt),
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
        let ct_value = lookup_ct6(&skel.maps.nat6_conn_timer, &ct_key)
            .expect("CT entry should have been created for egress");
        assert_eq!(ct_value.is_static, 1, "is_static should be 1 for static-backed CT");
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_EGRESS, "gress should be EGRESS");
    }

    #[test]
    fn udp_ingress_creates_ct_with_is_static_one() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-ct-create");
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
            &skel.maps.nat6_static_mappings,
            vec![StaticNatMappingV6Item {
                wan_port: 80,
                lan_port: 80,
                lan_ip: lan_host(),
                l4_protocol: 17, // UDP
            }],
        );

        // No pre-populated CT.

        let wan_npt_ip = Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap();
        let mut pkt = build_ipv6_udp(remote(), wan_npt_ip, 9999, 80);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&mut pkt),
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
        let ct_value = lookup_ct6(&skel.maps.nat6_conn_timer, &ct_key)
            .expect("CT entry should have been created for ingress");
        assert_eq!(ct_value.is_static, 1, "is_static should be 1 for static-backed ingress CT");
        assert_eq!(ct_value.gress, crate::NAT_MAPPING_INGRESS, "gress should be INGRESS",);
    }
}
