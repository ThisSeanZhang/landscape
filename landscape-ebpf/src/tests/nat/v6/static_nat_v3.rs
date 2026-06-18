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

fn wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::100").unwrap()
}

fn remote() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
}

fn wan_npt_addr() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f25::100").unwrap()
}

fn build_ipv6_tcp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .tcp(src_port, dst_port, 0x12345678, 65535);

    let payload = [0u8; 0];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
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

fn add_ct6_entry<T: MapCore>(
    timer_map: &T,
    l4proto: u8,
    client_suffix: [u8; 8],
    client_port: u16,
    id_byte: u8,
    client_prefix: [u8; 8],
    trigger_addr: Ipv6Addr,
    trigger_port: u16,
) {
    let key = types::nat_timer_key_v6 {
        client_suffix,
        client_port: client_port.to_be(),
        id_byte,
        l4_protocol: l4proto,
    };
    let mut value = types::nat_timer_value_v6 {
        server_status: 1,
        client_status: 1,
        is_allow_reuse: 1,
        ..Default::default()
    };
    value.trigger_addr = types::u_inet6_addr { bytes: trigger_addr.octets() };
    value.trigger_port = trigger_port.to_be();
    value.client_prefix = client_prefix;

    timer_map
        .update(unsafe { plain::as_bytes(&key) }, unsafe { plain::as_bytes(&value) }, MapFlags::ANY)
        .expect("failed to insert v3 v6 CT entry");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map_setting::nat::add_static_nat6_mapping;

    const TC_ACT_SHOT: i32 = 2;
    const LAN_CLIENT_SUFFIX: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    const LAN_CLIENT_PREFIX: [u8; 8] = [0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0xab, 0xc5];
    const LAN_ID_BYTE: u8 = 0x05;
    const WAN_NPT_PREFIX: [u8; 8] = [0x24, 0x09, 0x88, 0x88, 0x66, 0x66, 0x4f, 0x25];
    const LOCAL_CLIENT_SUFFIX: [u8; 8] = [0x00; 8];
    const LOCAL_CLIENT_PREFIX: [u8; 8] = [0x24, 0x09, 0x88, 0x88, 0x66, 0x66, 0x4f, 0x21];
    const LOCAL_ID_BYTE: u8 = 0x01;

    #[test]
    fn tcp_ingress_lan_host_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-lan");
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
                l4_protocol: 6,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            6,
            LAN_CLIENT_SUFFIX,
            80,
            LAN_ID_BYTE,
            LAN_CLIENT_PREFIX,
            remote(),
            9999,
        );

        let mut pkt = build_ipv6_tcp(remote(), wan_npt_addr(), 9999, 80);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(&dst.octets()[..8], &LAN_CLIENT_PREFIX, "dst prefix should be rewritten");
            assert_eq!(&dst.octets()[8..], &LAN_CLIENT_SUFFIX, "dst suffix should be preserved");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, 80, "dst_port should be unchanged");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_egress_lan_host_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-lan");
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
                l4_protocol: 6,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            6,
            LAN_CLIENT_SUFFIX,
            80,
            LAN_ID_BYTE,
            LAN_CLIENT_PREFIX,
            remote(),
            9999,
        );

        let mut pkt = build_ipv6_tcp(lan_host(), remote(), 80, 9999);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let src: Ipv6Addr = ipv6.source.into();
            assert_eq!(&src.octets()[..8], &WAN_NPT_PREFIX, "src prefix should be NPT-translated");
            assert_eq!(&src.octets()[8..], &LAN_CLIENT_SUFFIX, "src suffix should be preserved");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, 80, "src_port should be unchanged");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_ingress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-local");
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
                lan_ip: Ipv6Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            6,
            LOCAL_CLIENT_SUFFIX,
            80,
            LOCAL_ID_BYTE,
            LOCAL_CLIENT_PREFIX,
            remote(),
            9999,
        );

        let mut pkt = build_ipv6_tcp(remote(), wan_ip(), 9999, 80);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(dst, wan_ip(), "dst should stay on local router address");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, 80, "dst_port should be unchanged");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_egress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-local");
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
                lan_ip: Ipv6Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            6,
            LOCAL_CLIENT_SUFFIX,
            80,
            LOCAL_ID_BYTE,
            LOCAL_CLIENT_PREFIX,
            remote(),
            9999,
        );

        let mut pkt = build_ipv6_tcp(wan_ip(), remote(), 80, 9999);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let src: Ipv6Addr = ipv6.source.into();
            assert_eq!(src, wan_ip(), "src should stay on local router address");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, 80, "src_port should be unchanged");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn udp_ingress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-local");
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
                wan_port: 53,
                lan_port: 53,
                lan_ip: Ipv6Addr::UNSPECIFIED,
                l4_protocol: 17,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            17,
            LOCAL_CLIENT_SUFFIX,
            53,
            LOCAL_ID_BYTE,
            LOCAL_CLIENT_PREFIX,
            remote(),
            12345,
        );

        let mut pkt = build_ipv6_udp(remote(), wan_ip(), 12345, 53);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(dst, wan_ip(), "dst should stay on local router address");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.destination_port, 53, "dst_port should be unchanged");
        } else {
            panic!("expected UDP transport header in output");
        }
    }

    #[test]
    fn udp_egress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-local");
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
                wan_port: 53,
                lan_port: 53,
                lan_ip: Ipv6Addr::UNSPECIFIED,
                l4_protocol: 17,
            }],
        );

        add_ct6_entry(
            &skel.maps.nat6_conn_timer,
            17,
            LOCAL_CLIENT_SUFFIX,
            53,
            LOCAL_ID_BYTE,
            LOCAL_CLIENT_PREFIX,
            remote(),
            12345,
        );

        let mut pkt = build_ipv6_udp(wan_ip(), remote(), 53, 12345);
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

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let src: Ipv6Addr = ipv6.source.into();
            assert_eq!(src, wan_ip(), "src should stay on local router address");
        } else {
            panic!("expected IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.source_port, 53, "src_port should be unchanged");
        } else {
            panic!("expected UDP transport header in output");
        }
    }

    #[test]
    fn tcp_ingress_no_match_drop_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-static-v3-local");
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
                lan_ip: Ipv6Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );

        let mut pkt = build_ipv6_tcp(remote(), wan_ip(), 9999, 9090);
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
        assert_eq!(
            result.return_value as i32, TC_ACT_SHOT,
            "ingress with no matching mapping should return TC_ACT_SHOT(2)",
        );
    }
}
