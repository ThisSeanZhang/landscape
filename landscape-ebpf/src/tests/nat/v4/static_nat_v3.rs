use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
};

use etherparse::PacketBuilder;
use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{
    map_setting::{
        add_wan_ip,
        nat::{add_static_nat4_mapping_v3, StaticNatMappingV4Item},
    },
    map_types::{Nat4TimerKey, Nat4TimerValueV3},
    stages::nat::tc_nat_skel::TcNatSkelBuilder,
    tests::TestSkb,
    NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS,
};

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IFINDEX: u32 = 6;

fn build_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .tcp(src_port, dst_port, 0x12345678, 65535);

    let payload = [0u8; 0];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn build_ipv4_tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .tcp(src_port, dst_port, 0x12345678, 65535)
    .syn();

    let payload = [0u8; 0];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .udp(src_port, dst_port);

    let payload = [0u8; 8];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

#[allow(clippy::too_many_arguments)]
fn add_ct_entry<T: MapCore>(
    timer_map: &T,
    l4proto: u8,
    src_addr: Ipv4Addr,
    src_port: u16,
    nat_addr: Ipv4Addr,
    nat_port: u16,
    client_addr: Ipv4Addr,
    client_port: u16,
    gress: u8,
) {
    let key = Nat4TimerKey {
        l4proto,
        _pad: [0; 3],
        src_addr: src_addr.to_bits().to_be(),
        dst_addr: nat_addr.to_bits().to_be(),
        src_port: src_port.to_be(),
        dst_port: nat_port.to_be(),
    };
    let value = Nat4TimerValueV3 {
        server_status: 1,
        client_status: 1,
        gress,
        client_addr: client_addr.to_bits().to_be(),
        client_port: client_port.to_be(),
        ifindex: IFINDEX,
        ..Default::default()
    };

    timer_map
        .update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
        .expect("failed to insert CT entry");
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_SHOT: i32 = 2;

    #[test]
    fn tcp_ingress_lan_host_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-lan");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: LAN_HOST,
                l4_protocol: 6,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            6,
            REMOTE_IP,
            9999,
            WAN_IP,
            8080,
            LAN_HOST,
            80,
            NAT_MAPPING_INGRESS,
        );

        let pkt = build_ipv4_tcp(REMOTE_IP, WAN_IP, 9999, 8080);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, LAN_HOST, "dst_ip should be rewritten to LAN host");
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, 80, "dst_port should be rewritten to 80");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_egress_lan_host_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-lan");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: LAN_HOST,
                l4_protocol: 6,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            6,
            REMOTE_IP,
            9999,
            WAN_IP,
            8080,
            LAN_HOST,
            80,
            NAT_MAPPING_EGRESS,
        );

        let pkt = build_ipv4_tcp(LAN_HOST, REMOTE_IP, 80, 9999);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let src: Ipv4Addr = ipv4.source.into();
            assert_eq!(src, WAN_IP, "src_ip should be rewritten to WAN IP");
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, 8080, "src_port should be rewritten to 8080");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_ingress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            6,
            REMOTE_IP,
            9999,
            WAN_IP,
            8080,
            WAN_IP,
            80,
            NAT_MAPPING_INGRESS,
        );

        let pkt = build_ipv4_tcp(REMOTE_IP, WAN_IP, 9999, 8080);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, WAN_IP, "dst_ip should stay WAN_IP, not 0.0.0.0 (OK path passthrough)");
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, 80, "dst_port should be rewritten to 80");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_ingress_local_router_v3_create_path_preserves_dst_ip() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local-create");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        // Static mapping with lan_ip = 0.0.0.0 (passthrough / local router)
        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );

        // No pre-seeded CT — exercise the create path (CT_RESOLVE_MISS)
        let pkt = build_ipv4_tcp_syn(REMOTE_IP, WAN_IP, 443, 8080);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        // dst IP must stay WAN_IP (passthrough), NOT become 0.0.0.0
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, WAN_IP, "dst_ip should stay WAN_IP, not 0.0.0.0");
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, 80, "dst_port should be rewritten to 80");
        } else {
            panic!("expected TCP transport header in output");
        }

        // verify CT was created and stores the concrete dst (WAN_IP) as client_addr
        let timer_key = Nat4TimerKey {
            l4proto: 6,
            _pad: [0; 3],
            src_addr: REMOTE_IP.to_bits().to_be(),
            dst_addr: WAN_IP.to_bits().to_be(),
            src_port: 443u16.to_be(),
            dst_port: 8080u16.to_be(),
        };
        let timer_bytes = skel
            .maps
            .nat4_timer_map
            .lookup(timer_key.as_bytes(), MapFlags::ANY)
            .expect("lookup ct");
        let timer_bytes = timer_bytes.expect("ingress should create CT");
        let timer = Nat4TimerValueV3::read_from_bytes(&timer_bytes).unwrap();
        assert_eq!(
            timer.client_addr,
            WAN_IP.to_bits().to_be(),
            "CT client_addr must be WAN_IP, not 0"
        );
        assert_eq!(timer.client_port, 80u16.to_be(), "CT client_port must be 80");
    }

    #[test]
    fn tcp_egress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            6,
            REMOTE_IP,
            9999,
            WAN_IP,
            8080,
            WAN_IP,
            80,
            NAT_MAPPING_EGRESS,
        );

        let pkt = build_ipv4_tcp(WAN_IP, REMOTE_IP, 80, 9999);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, 8080, "src_port should be rewritten to 8080");
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn udp_ingress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 5353,
                lan_port: 53,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 17,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            17,
            REMOTE_IP,
            12345,
            WAN_IP,
            5353,
            WAN_IP,
            53,
            NAT_MAPPING_INGRESS,
        );

        let pkt = build_ipv4_udp(REMOTE_IP, WAN_IP, 12345, 5353);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.destination_port, 53, "dst_port should be rewritten to 53");
        } else {
            panic!("expected UDP transport header in output");
        }
    }

    #[test]
    fn udp_egress_local_router_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 5353,
                lan_port: 53,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 17,
            }],
        );
        add_ct_entry(
            &skel.maps.nat4_timer_map,
            17,
            REMOTE_IP,
            12345,
            WAN_IP,
            5353,
            WAN_IP,
            53,
            NAT_MAPPING_EGRESS,
        );

        let pkt = build_ipv4_udp(WAN_IP, REMOTE_IP, 53, 12345);
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

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Udp(udp)) = pkt_out.transport {
            assert_eq!(udp.source_port, 5353, "src_port should be rewritten to 5353");
        } else {
            panic!("expected UDP transport header in output");
        }
    }

    #[test]
    fn tcp_ingress_no_match_drop_v3() {
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v4-static-v3-local");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = builder.open(&mut open_object).unwrap();
        let skel = open_skel.load().unwrap();

        add_wan_ip(
            &skel.maps.wan_ip_binding,
            IFINDEX,
            IpAddr::V4(WAN_IP),
            None,
            24,
            Some(MacAddr::broadcast()),
        );

        add_static_nat4_mapping_v3(
            &skel.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: Ipv4Addr::UNSPECIFIED,
                l4_protocol: 6,
            }],
        );

        let pkt = build_ipv4_tcp(REMOTE_IP, WAN_IP, 9999, 9090);
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };

        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
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
