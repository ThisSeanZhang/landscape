use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr},
};

use etherparse::{icmpv4, Icmpv4Type, PacketBuilder};
use landscape_common::iface::nat::NatConfig;
use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};
use zerocopy::IntoBytes;

use crate::{
    map_setting::{
        add_wan_ip,
        nat::NatMappingKeyV4,
        nat::{add_static_nat4_mapping_v3, StaticNatMappingV4Item},
    },
    stages::nat::tc_nat_skel::{types, TcNatSkelBuilder},
    tests::TestSkb,
    NAT_MAPPING_EGRESS, NAT_MAPPING_INGRESS,
};

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const SECOND_LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 101);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(50, 18, 88, 205);
const IFINDEX: u32 = 6;
const LAN_PORT: u16 = 56186;
const SECOND_LAN_PORT: u16 = 56187;
const NAT_PORT: u16 = 40000;
const ALT_NAT_PORT: u16 = 40001;
const GENERATION: u16 = 7;

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

fn build_ipv4_icmp_time_exceeded(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    quoted_ipv4_packet: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv4(src.octets(), dst.octets(), 64)
    .icmpv4(Icmpv4Type::TimeExceeded(icmpv4::TimeExceededCode::TtlExceededInTransit));

    let mut buf = Vec::with_capacity(builder.size(quoted_ipv4_packet.len()));
    builder.write(&mut buf, quoted_ipv4_packet).unwrap();
    buf
}

fn build_quoted_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    build_ipv4_tcp(src, dst, src_port, dst_port)[14..].to_vec()
}

fn parse_inner_ipv4_from_icmp(packet: &[u8]) -> etherparse::PacketHeaders<'_> {
    let outer = etherparse::PacketHeaders::from_ethernet_slice(packet).expect("parse outer packet");
    let ipv4 = match outer.net {
        Some(etherparse::NetHeaders::Ipv4(ipv4, _)) => ipv4,
        _ => panic!("expected outer IPv4 header"),
    };
    let inner_offset = 14 + ipv4.header_len() + 8;
    etherparse::PacketHeaders::from_ip_slice(&packet[inner_offset..]).expect("parse quoted packet")
}

fn put_v3_state<T: MapCore>(
    map: &T,
    l4proto: u8,
    nat_addr: Ipv4Addr,
    nat_port: u16,
    state_ref: u64,
) {
    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };
    let bytes = map
        .lookup(unsafe { plain::as_bytes(&ingress_key) }, MapFlags::ANY)
        .expect("lookup v3 ingress entry")
        .expect("missing v3 ingress entry");
    let mut value =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<types::nat4_mapping_value_v3>()) };
    value.generation = GENERATION;
    value.state_ref = state_ref;

    map.update(
        unsafe { plain::as_bytes(&ingress_key) },
        unsafe { plain::as_bytes(&value) },
        MapFlags::ANY,
    )
    .expect("insert v3 state");
}

fn add_v3_state<T: MapCore>(map: &T, l4proto: u8, nat_addr: Ipv4Addr, nat_port: u16) {
    put_v3_state(map, l4proto, nat_addr, nat_port, ((1u64) << 56) | 1);
}

fn delete_v3_state<T: MapCore>(map: &T, l4proto: u8, nat_addr: Ipv4Addr, nat_port: u16) {
    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };

    let _ = map.delete(unsafe { plain::as_bytes(&ingress_key) });
}

fn add_v3_ct<T: MapCore>(
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
    let key = types::nat_timer_key_v4 {
        l4proto,
        _pad: [0; 3],
        pair_ip: types::inet4_pair {
            src_addr: types::inet4_addr { addr: src_addr.to_bits().to_be() },
            dst_addr: types::inet4_addr { addr: nat_addr.to_bits().to_be() },
            src_port: src_port.to_be(),
            dst_port: nat_port.to_be(),
        },
    };

    let mut value = types::nat4_timer_value_v3::default();
    value.client_addr = types::inet4_addr { addr: client_addr.to_bits().to_be() };
    value.client_port = client_port.to_be();
    value.client_status = 1;
    value.server_status = 1;
    value.gress = gress;
    value.generation_snapshot = GENERATION;
    value.ifindex = IFINDEX;

    timer_map
        .update(unsafe { plain::as_bytes(&key) }, unsafe { plain::as_bytes(&value) }, MapFlags::ANY)
        .expect("insert v3 ct");
}

fn delete_v3_ct<T: MapCore>(
    timer_map: &T,
    l4proto: u8,
    src_addr: Ipv4Addr,
    src_port: u16,
    nat_addr: Ipv4Addr,
    nat_port: u16,
) {
    let key = types::nat_timer_key_v4 {
        l4proto,
        _pad: [0; 3],
        pair_ip: types::inet4_pair {
            src_addr: types::inet4_addr { addr: src_addr.to_bits().to_be() },
            dst_addr: types::inet4_addr { addr: nat_addr.to_bits().to_be() },
            src_port: src_port.to_be(),
            dst_port: nat_port.to_be(),
        },
    };

    let _ = timer_map.delete(unsafe { plain::as_bytes(&key) });
}

fn add_dynamic_mapping_pair<T: MapCore>(
    map: &T,
    l4proto: u8,
    lan_addr: Ipv4Addr,
    lan_port: u16,
    nat_addr: Ipv4Addr,
    nat_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) {
    let egress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_EGRESS,
        l4proto,
        from_port: lan_port.to_be(),
        from_addr: lan_addr.to_bits().to_be(),
    };
    let egress_val = types::nat4_mapping_value_v3 {
        state_ref: 0,
        addr: nat_addr.to_bits().to_be(),
        trigger_addr: remote_addr.to_bits().to_be(),
        port: nat_port.to_be(),
        trigger_port: remote_port.to_be(),
        generation: 0,
        is_static: 0,
        is_allow_reuse: 1,
    };

    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };
    let ingress_val = types::nat4_mapping_value_v3 {
        state_ref: ((1u64) << 56) | 1,
        addr: lan_addr.to_bits().to_be(),
        trigger_addr: remote_addr.to_bits().to_be(),
        port: lan_port.to_be(),
        trigger_port: remote_port.to_be(),
        generation: GENERATION,
        is_static: 0,
        is_allow_reuse: 1,
    };

    map.update(
        unsafe { plain::as_bytes(&egress_key) },
        unsafe { plain::as_bytes(&egress_val) },
        MapFlags::ANY,
    )
    .expect("insert egress mapping");
    map.update(
        unsafe { plain::as_bytes(&ingress_key) },
        unsafe { plain::as_bytes(&ingress_val) },
        MapFlags::ANY,
    )
    .expect("insert ingress mapping");
}

fn delete_dynamic_mapping_pair<T: MapCore>(
    map: &T,
    l4proto: u8,
    lan_addr: Ipv4Addr,
    lan_port: u16,
    nat_addr: Ipv4Addr,
    nat_port: u16,
) {
    let egress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_EGRESS,
        l4proto,
        from_port: lan_port.to_be(),
        from_addr: lan_addr.to_bits().to_be(),
    };
    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };

    let _ = map.delete(unsafe { plain::as_bytes(&egress_key) });
    let _ = map.delete(unsafe { plain::as_bytes(&ingress_key) });
}

fn push_v3_free_port<T: MapCore>(queue_map: &T, port: u16, last_generation: u16) {
    let key: [u8; 0] = [];
    let value = types::nat4_port_queue_value_v3 { port: port.to_be(), last_generation };

    queue_map
        .update(&key, unsafe { plain::as_bytes(&value) }, MapFlags::ANY)
        .expect("push v3 free port");
}

fn clear_v3_free_port_queue<T: MapCore>(queue_map: &T) {
    let key: [u8; 0] = [];
    while queue_map.lookup_and_delete(&key).expect("clear v3 free-port queue").is_some() {}
}

fn clear_all_v3_map_entries<T: MapCore>(map: &T) {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        map.delete(&key).expect("clear v3 map entry");
    }
}

fn read_v3_ingress_mapping<T: MapCore>(
    map: &T,
    l4proto: u8,
    nat_addr: Ipv4Addr,
    nat_port: u16,
) -> types::nat4_mapping_value_v3 {
    let ingress_key = NatMappingKeyV4 {
        gress: NAT_MAPPING_INGRESS,
        l4proto,
        from_port: nat_port.to_be(),
        from_addr: nat_addr.to_bits().to_be(),
    };
    let bytes = map
        .lookup(unsafe { plain::as_bytes(&ingress_key) }, MapFlags::ANY)
        .expect("lookup v3 ingress mapping")
        .expect("ingress mapping should exist");
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<types::nat4_mapping_value_v3>()) }
}

fn reset_dynamic_nat_v3_runtime_for_test<M1, M2, M3, M4, M5>(
    nat4_dyn_map: &M1,
    timer_map: &M2,
    tcp_queue: &M3,
    udp_queue: &M4,
    icmp_queue: &M5,
    config: &NatConfig,
) where
    M1: MapCore,
    M2: MapCore,
    M3: MapCore,
    M4: MapCore,
    M5: MapCore,
{
    clear_all_v3_map_entries(timer_map);
    clear_all_v3_map_entries(nat4_dyn_map);

    clear_v3_free_port_queue(tcp_queue);
    clear_v3_free_port_queue(udp_queue);
    clear_v3_free_port_queue(icmp_queue);

    for port in config.tcp_range.start..=config.tcp_range.end {
        push_v3_free_port(tcp_queue, port, 0);
    }
    for port in config.udp_range.start..=config.udp_range.end {
        push_v3_free_port(udp_queue, port, 0);
    }
    for port in config.icmp_in_range.start..=config.icmp_in_range.end {
        push_v3_free_port(icmp_queue, port, 0);
    }
}

fn peek_v3_free_port<T: MapCore>(queue_map: &T) -> Option<u16> {
    let key: [u8; 0] = [];
    let value = queue_map.lookup(&key, MapFlags::ANY).expect("peek v3 free-port queue")?;
    let value = unsafe {
        std::ptr::read_unaligned(value.as_ptr().cast::<types::nat4_port_queue_value_v3>())
    };
    Some(u16::from_be(value.port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::nat::NAT_V3_TEST_LOCK;

    #[test]
    fn tcp_egress_dynamic_v3_existing_state_and_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            ALT_NAT_PORT,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, ALT_NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, ALT_NAT_PORT);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_EGRESS,
        );

        let mut pkt = build_ipv4_tcp(LAN_HOST, REMOTE_IP, LAN_PORT, 443);
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

        assert_eq!(result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let src: Ipv4Addr = ipv4.source.into();
            assert_eq!(src, WAN_IP);
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, NAT_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_egress_dynamic_v3_icmp_error_uses_inner_l4_protocol() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_EGRESS,
        );

        let quoted = build_quoted_ipv4_tcp(REMOTE_IP, LAN_HOST, 443, LAN_PORT);
        let mut pkt = build_ipv4_icmp_time_exceeded(LAN_HOST, REMOTE_IP, &quoted);
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

        assert_eq!(result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let src: Ipv4Addr = ipv4.source.into();
            assert_eq!(src, WAN_IP);
        } else {
            panic!("expected IPv4 header in output");
        }

        let quoted_out = parse_inner_ipv4_from_icmp(&packet_out);
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = quoted_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, WAN_IP);
        } else {
            panic!("expected quoted IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = quoted_out.transport {
            assert_eq!(tcp.destination_port, NAT_PORT);
        } else {
            panic!("expected quoted TCP header in output");
        }
    }

    #[test]
    fn tcp_egress_dynamic_v3_missing_ingress_cleans_stale_pair_for_non_initiating_packet() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            ALT_NAT_PORT,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, ALT_NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, ALT_NAT_PORT);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);

        let mut pkt = build_ipv4_tcp(LAN_HOST, REMOTE_IP, LAN_PORT, 443);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let input = ProgramInput {
            data_in: Some(&mut pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_egress.test_run(input).expect("test_run failed");

        assert_eq!(
            result.return_value as i32, 2,
            "stale dynamic pair should drop non-initiating packet"
        );

        let egress_key = NatMappingKeyV4 {
            gress: NAT_MAPPING_EGRESS,
            l4proto: 6,
            from_port: LAN_PORT.to_be(),
            from_addr: LAN_HOST.to_bits().to_be(),
        };
        let stale_mapping = skel
            .maps
            .nat4_dyn_map
            .lookup(unsafe { plain::as_bytes(&egress_key) }, MapFlags::ANY)
            .expect("lookup stale egress mapping");
        assert!(stale_mapping.is_none(), "stale egress mapping should be deleted");
    }

    #[test]
    fn tcp_egress_dynamic_v3_missing_ingress_recreates_mapping_for_syn() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, NAT_PORT, 0);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);

        let mut pkt = build_ipv4_tcp_syn(LAN_HOST, REMOTE_IP, LAN_PORT, 443);
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

        assert_eq!(result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, NAT_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(ingress.generation, 1);
        assert_eq!(ingress.state_ref, ((1u64) << 56) | 1);
    }

    #[test]
    fn tcp_egress_dynamic_v3_mismatched_ingress_owner_cleans_stale_pair() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );

        let mut pkt = build_ipv4_tcp(LAN_HOST, REMOTE_IP, LAN_PORT, 443);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let input = ProgramInput {
            data_in: Some(&mut pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_egress.test_run(input).expect("test_run failed");

        assert_eq!(
            result.return_value as i32, 2,
            "ingress owner mismatch should be treated as a stale egress mapping"
        );

        let first_egress_key = NatMappingKeyV4 {
            gress: NAT_MAPPING_EGRESS,
            l4proto: 6,
            from_port: LAN_PORT.to_be(),
            from_addr: LAN_HOST.to_bits().to_be(),
        };
        let first_mapping = skel
            .maps
            .nat4_dyn_map
            .lookup(unsafe { plain::as_bytes(&first_egress_key) }, MapFlags::ANY)
            .expect("lookup first stale egress mapping");
        assert!(first_mapping.is_none(), "stale egress mapping should be deleted");

        let second_egress_key = NatMappingKeyV4 {
            gress: NAT_MAPPING_EGRESS,
            l4proto: 6,
            from_port: SECOND_LAN_PORT.to_be(),
            from_addr: SECOND_LAN_HOST.to_bits().to_be(),
        };
        let second_mapping = skel
            .maps
            .nat4_dyn_map
            .lookup(unsafe { plain::as_bytes(&second_egress_key) }, MapFlags::ANY)
            .expect("lookup second egress mapping");
        assert!(second_mapping.is_some(), "unrelated egress mapping should be preserved");

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(Ipv4Addr::from(u32::from_be(ingress.addr)), SECOND_LAN_HOST);
        assert_eq!(u16::from_be(ingress.port), SECOND_LAN_PORT);
    }

    #[test]
    fn tcp_ingress_dynamic_v3_reuse_creates_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);

        let mut pkt = build_ipv4_tcp_syn(REMOTE_IP, WAN_IP, 443, NAT_PORT);
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

        assert_eq!(result.return_value as i32, 0);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, LAN_HOST);
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.destination_port, LAN_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(ingress.generation, GENERATION);
        assert_eq!(ingress.state_ref, ((1u64) << 56) | 2, "reuse ingress should incref state_ref");

        let timer_key = types::nat_timer_key_v4 {
            l4proto: 6,
            _pad: [0; 3],
            pair_ip: types::inet4_pair {
                src_addr: types::inet4_addr { addr: REMOTE_IP.to_bits().to_be() },
                dst_addr: types::inet4_addr { addr: WAN_IP.to_bits().to_be() },
                src_port: 443u16.to_be(),
                dst_port: NAT_PORT.to_be(),
            },
        };
        let timer_bytes = skel
            .maps
            .nat4_mapping_timer_v3
            .lookup(unsafe { plain::as_bytes(&timer_key) }, MapFlags::ANY)
            .expect("lookup v3 ct");
        let timer_bytes = timer_bytes.expect("ingress reuse should create ct");
        let timer = unsafe {
            std::ptr::read_unaligned(timer_bytes.as_ptr().cast::<types::nat4_timer_value_v3>())
        };
        assert_eq!(timer.generation_snapshot, GENERATION);
        assert_eq!(timer.client_port, LAN_PORT.to_be());
    }

    #[test]
    fn tcp_ingress_dynamic_v3_icmp_error_uses_inner_l4_protocol() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_INGRESS,
        );

        let quoted = build_quoted_ipv4_tcp(WAN_IP, REMOTE_IP, NAT_PORT, 443);
        let mut pkt = build_ipv4_icmp_time_exceeded(REMOTE_IP, WAN_IP, &quoted);
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

        assert_eq!(result.return_value as i32, 0);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, LAN_HOST);
        } else {
            panic!("expected IPv4 header in output");
        }

        let quoted_out = parse_inner_ipv4_from_icmp(&packet_out);
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = quoted_out.net {
            let src: Ipv4Addr = ipv4.source.into();
            assert_eq!(src, LAN_HOST);
        } else {
            panic!("expected quoted IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = quoted_out.transport {
            assert_eq!(tcp.source_port, LAN_PORT);
        } else {
            panic!("expected quoted TCP header in output");
        }
    }

    #[test]
    fn tcp_ingress_dynamic_v3_closed_blocks_new_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        put_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT, ((2u64) << 56) | 1);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);

        let mut pkt = build_ipv4_tcp_syn(REMOTE_IP, WAN_IP, 443, NAT_PORT);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let input = ProgramInput {
            data_in: Some(&mut pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_ingress.test_run(input).expect("test_run failed");

        assert_eq!(result.return_value as i32, 2, "closed mapping should reject new ingress CT");

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(ingress.state_ref, ((2u64) << 56) | 1);
    }

    #[test]
    fn tcp_ingress_dynamic_v3_active_zero_blocks_new_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        put_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT, ((1u64) << 56) | 0);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);

        let mut pkt = build_ipv4_tcp_syn(REMOTE_IP, WAN_IP, 443, NAT_PORT);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let input = ProgramInput {
            data_in: Some(&mut pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_ingress.test_run(input).expect("test_run failed");

        assert_eq!(result.return_value as i32, 2, "active|0 mapping should reject new ingress CT");

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(ingress.state_ref, ((1u64) << 56) | 0);

        let timer_key = types::nat_timer_key_v4 {
            l4proto: 6,
            _pad: [0; 3],
            pair_ip: types::inet4_pair {
                src_addr: types::inet4_addr { addr: REMOTE_IP.to_bits().to_be() },
                dst_addr: types::inet4_addr { addr: WAN_IP.to_bits().to_be() },
                src_port: 443u16.to_be(),
                dst_port: NAT_PORT.to_be(),
            },
        };
        let timer_bytes = skel
            .maps
            .nat4_mapping_timer_v3
            .lookup(unsafe { plain::as_bytes(&timer_key) }, MapFlags::ANY)
            .expect("lookup v3 ct");
        assert!(timer_bytes.is_none(), "active|0 ingress should not create ct");
    }

    #[test]
    fn tcp_ingress_dynamic_v3_closed_allows_existing_ct() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        put_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT, ((2u64) << 56) | 1);
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_INGRESS,
        );

        let mut pkt = build_ipv4_tcp_syn(REMOTE_IP, WAN_IP, 443, NAT_PORT);
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

        assert_eq!(result.return_value as i32, 0);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let dst: Ipv4Addr = ipv4.destination.into();
            assert_eq!(dst, LAN_HOST);
        } else {
            panic!("expected IPv4 header in output");
        }

        let ingress = read_v3_ingress_mapping(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        assert_eq!(
            ingress.state_ref,
            ((2u64) << 56) | 1,
            "existing ct should not incref closed mapping"
        );
    }

    #[test]
    fn tcp_egress_static_v3_creates_ct_without_dynamic_state() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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
            &skel.maps.nat4_st_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: LAN_HOST,
                l4_protocol: 6,
            }],
        );

        let mut pkt = build_ipv4_tcp_syn(LAN_HOST, REMOTE_IP, 80, 443);
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

        assert_eq!(result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::NetHeaders::Ipv4(ipv4, _)) = pkt_out.net {
            let src: Ipv4Addr = ipv4.source.into();
            assert_eq!(src, WAN_IP);
        } else {
            panic!("expected IPv4 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, 8080);
        } else {
            panic!("expected TCP transport header in output");
        }

        let timer_key = types::nat_timer_key_v4 {
            l4proto: 6,
            _pad: [0; 3],
            pair_ip: types::inet4_pair {
                src_addr: types::inet4_addr { addr: REMOTE_IP.to_bits().to_be() },
                dst_addr: types::inet4_addr { addr: WAN_IP.to_bits().to_be() },
                src_port: 443u16.to_be(),
                dst_port: 8080u16.to_be(),
            },
        };
        let timer_bytes = skel
            .maps
            .nat4_mapping_timer_v3
            .lookup(unsafe { plain::as_bytes(&timer_key) }, MapFlags::ANY)
            .expect("lookup static v3 ct");
        let timer_bytes = timer_bytes.expect("static egress should create ct");
        let timer = unsafe {
            std::ptr::read_unaligned(timer_bytes.as_ptr().cast::<types::nat4_timer_value_v3>())
        };
        assert_eq!(timer.client_port, 80u16.to_be());
    }

    #[test]
    fn tcp_egress_dynamic_v3_restart_queue_conflict_drops_first_flow_then_uses_next_port() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            ALT_NAT_PORT,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, ALT_NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, ALT_NAT_PORT);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_EGRESS,
        );

        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, NAT_PORT, 0);
        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, ALT_NAT_PORT, 0);

        let mut first_pkt = build_ipv4_tcp_syn(SECOND_LAN_HOST, REMOTE_IP, SECOND_LAN_PORT, 443);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let first_input = ProgramInput {
            data_in: Some(&mut first_pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let first_result =
            skel.progs.tc_nat_wan_egress.test_run(first_input).expect("test_run failed");

        assert_eq!(
            first_result.return_value as i32, 2,
            "the first new flow should drop when restart queue re-issues an in-use NAT port"
        );

        let second_egress_key = NatMappingKeyV4 {
            gress: NAT_MAPPING_EGRESS,
            l4proto: 6,
            from_port: SECOND_LAN_PORT.to_be(),
            from_addr: SECOND_LAN_HOST.to_bits().to_be(),
        };
        let second_mapping = skel
            .maps
            .nat4_dyn_map
            .lookup(unsafe { plain::as_bytes(&second_egress_key) }, MapFlags::ANY)
            .expect("lookup second flow mapping after conflict");
        assert!(
            second_mapping.is_none(),
            "failed allocation should not leave a half-created egress mapping behind"
        );
        assert_eq!(
            peek_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3),
            Some(ALT_NAT_PORT),
            "after a failed allocation the queue advances to the next available port"
        );

        let mut second_pkt = build_ipv4_tcp_syn(SECOND_LAN_HOST, REMOTE_IP, SECOND_LAN_PORT, 443);
        let mut packet_out = vec![0u8; second_pkt.len()];
        let second_input = ProgramInput {
            data_in: Some(&mut second_pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let second_result =
            skel.progs.tc_nat_wan_egress.test_run(second_input).expect("test_run failed");

        assert_eq!(second_result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, ALT_NAT_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn tcp_egress_dynamic_v3_restart_without_timer_drops_first_flow_then_uses_next_port() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            ALT_NAT_PORT,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, ALT_NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, ALT_NAT_PORT);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);

        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, NAT_PORT, 0);
        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, ALT_NAT_PORT, 0);

        let stale_timer_key = types::nat_timer_key_v4 {
            l4proto: 6,
            _pad: [0; 3],
            pair_ip: types::inet4_pair {
                src_addr: types::inet4_addr { addr: REMOTE_IP.to_bits().to_be() },
                dst_addr: types::inet4_addr { addr: WAN_IP.to_bits().to_be() },
                src_port: 443u16.to_be(),
                dst_port: NAT_PORT.to_be(),
            },
        };
        let stale_timer = skel
            .maps
            .nat4_mapping_timer_v3
            .lookup(unsafe { plain::as_bytes(&stale_timer_key) }, MapFlags::ANY)
            .expect("lookup stale timer");
        assert!(stale_timer.is_none(), "this scenario requires the old timer to be missing");

        let mut first_pkt = build_ipv4_tcp_syn(SECOND_LAN_HOST, REMOTE_IP, SECOND_LAN_PORT, 443);
        let mut ctx = TestSkb::default();
        ctx.ifindex = IFINDEX;

        let first_input = ProgramInput {
            data_in: Some(&mut first_pkt),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: None,
            data_out: None,
            ..Default::default()
        };

        let first_result =
            skel.progs.tc_nat_wan_egress.test_run(first_input).expect("test_run failed");

        assert_eq!(
            first_result.return_value as i32, 2,
            "stale mapping without a timer should still block the first reissued NAT port"
        );
        assert_eq!(
            peek_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3),
            Some(ALT_NAT_PORT),
            "without a timer the failed stale port is removed and the next queued port becomes available"
        );

        let mut second_pkt = build_ipv4_tcp_syn(SECOND_LAN_HOST, REMOTE_IP, SECOND_LAN_PORT, 443);
        let mut packet_out = vec![0u8; second_pkt.len()];
        let second_input = ProgramInput {
            data_in: Some(&mut second_pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let second_result =
            skel.progs.tc_nat_wan_egress.test_run(second_input).expect("test_run failed");

        assert_eq!(second_result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, ALT_NAT_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }
    }

    #[test]
    fn reset_dynamic_nat_v3_runtime_clears_stale_state_and_restores_first_flow() {
        let _guard = NAT_V3_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut builder = TcNatSkelBuilder::default();
        let pin_root = crate::tests::nat::isolated_pin_root("nat-v4-dynamic-v3");
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

        clear_v3_free_port_queue(&skel.maps.nat4_tcp_free_ports_v3);
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            NAT_PORT,
        );
        delete_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            SECOND_LAN_HOST,
            SECOND_LAN_PORT,
            WAN_IP,
            ALT_NAT_PORT,
        );
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        delete_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, ALT_NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, NAT_PORT);
        delete_v3_ct(&skel.maps.nat4_mapping_timer_v3, 6, REMOTE_IP, 443, WAN_IP, ALT_NAT_PORT);

        add_dynamic_mapping_pair(
            &skel.maps.nat4_dyn_map,
            6,
            LAN_HOST,
            LAN_PORT,
            WAN_IP,
            NAT_PORT,
            REMOTE_IP,
            443,
        );
        add_v3_state(&skel.maps.nat4_dyn_map, 6, WAN_IP, NAT_PORT);
        add_v3_ct(
            &skel.maps.nat4_mapping_timer_v3,
            6,
            REMOTE_IP,
            443,
            WAN_IP,
            NAT_PORT,
            LAN_HOST,
            LAN_PORT,
            NAT_MAPPING_EGRESS,
        );
        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, NAT_PORT, 0);
        push_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3, ALT_NAT_PORT, 0);

        let config = NatConfig {
            tcp_range: NAT_PORT..ALT_NAT_PORT,
            udp_range: 45000..45001,
            icmp_in_range: 46000..46001,
        };
        reset_dynamic_nat_v3_runtime_for_test(
            &skel.maps.nat4_dyn_map,
            &skel.maps.nat4_mapping_timer_v3,
            &skel.maps.nat4_tcp_free_ports_v3,
            &skel.maps.nat4_udp_free_ports_v3,
            &skel.maps.nat4_icmp_free_ports_v3,
            &config,
        );

        let stale_ingress_key = NatMappingKeyV4 {
            gress: NAT_MAPPING_INGRESS,
            l4proto: 6,
            from_port: NAT_PORT.to_be(),
            from_addr: WAN_IP.to_bits().to_be(),
        };
        let stale_mapping = skel
            .maps
            .nat4_dyn_map
            .lookup(unsafe { plain::as_bytes(&stale_ingress_key) }, MapFlags::ANY)
            .expect("lookup stale mapping after cleanup");
        assert!(stale_mapping.is_none(), "cleanup should remove stale dynamic mappings");
        assert_eq!(
            peek_v3_free_port(&skel.maps.nat4_tcp_free_ports_v3),
            Some(NAT_PORT),
            "cleanup should reseed the queue from the configured port range"
        );

        let mut pkt = build_ipv4_tcp_syn(SECOND_LAN_HOST, REMOTE_IP, SECOND_LAN_PORT, 443);
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

        assert_eq!(result.return_value as i32, -1);

        let pkt_out = etherparse::PacketHeaders::from_ethernet_slice(&packet_out)
            .expect("parse output packet");
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
            assert_eq!(tcp.source_port, NAT_PORT);
        } else {
            panic!("expected TCP transport header in output");
        }
    }
}
