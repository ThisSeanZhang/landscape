use std::{mem::MaybeUninit, net::Ipv6Addr, str::FromStr};

use etherparse::{IcmpEchoHeader, Icmpv6Type, PacketBuilder, PacketHeaders, icmpv6};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, IntoBytes};

use super::TCP_BOTH_SYN;
use crate::{
    maps::{Nat6MappingKey, Nat6MappingValue, Nat6TimerKey, Nat6TimerValue},
    skel::tc_nat6::TcNat6SkelBuilder,
    tests::TestSkb,
};

const IFINDEX: u32 = 6;
const L4PROTO_TCP: u8 = 6;
const CLIENT_PORT: u16 = 12345;
const TIMER_ACTIVE: u64 = 20;
const TIMER_WAIT_TIMEOUT: u64 = 40;
const TIMER_CLEAN_START: u64 = 50;
const PREFIX60_WAN_NPT_PREFIX: [u8; 8] = [0x24, 0x09, 0x88, 0x88, 0x66, 0x66, 0x4f, 0x25];

fn wan_ip() -> Ipv6Addr {
    Ipv6Addr::from_str("2409:8888:6666:4f21::").unwrap()
}

fn lan_host() -> Ipv6Addr {
    Ipv6Addr::from_str("fd00:1234:5678:abc5::200").unwrap()
}

fn remote() -> Ipv6Addr {
    Ipv6Addr::from_str("2001:db8:2::1").unwrap()
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

fn build_ipv6_icmpv6_echo(src: Ipv6Addr, dst: Ipv6Addr, id: u16, request: bool) -> Vec<u8> {
    let echo = IcmpEchoHeader { id, seq: 1 };
    let ty = if request { Icmpv6Type::EchoRequest(echo) } else { Icmpv6Type::EchoReply(echo) };
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .icmpv6(ty);

    let mut buf = Vec::with_capacity(builder.size(0));
    builder.write(&mut buf, &[]).unwrap();
    buf
}

fn npt_id_mask(prefix_len: u8) -> u8 {
    if prefix_len >= 64 { 0 } else { ((1u16 << (64 - prefix_len)) - 1) as u8 }
}

fn timer_key_for(
    src: Ipv6Addr,
    client_port: u16,
    prefix_len: u8,
    dst: Ipv6Addr,
    port: u16,
) -> Nat6TimerKey {
    let bytes = src.octets();
    let mut client_suffix = [0u8; 8];
    client_suffix.copy_from_slice(&bytes[8..]);

    Nat6TimerKey {
        local: Nat6MappingKey {
            client_suffix,
            client_port: client_port.to_be(),
            id_byte: bytes[7] & npt_id_mask(prefix_len),
            l4_protocol: L4PROTO_TCP,
        },
        remote_addr: dst.octets(),
        remote_port: port.to_be(),
        _pad: 0,
    }
}

fn add_ct6_entry<T: MapCore>(timer_map: &T, key: &Nat6TimerKey, src: Ipv6Addr) {
    let mut value = Nat6TimerValue {
        tcp_flags: TCP_BOTH_SYN,
        need_prefix_replace: 1,
        ..Default::default()
    };
    value.client_prefix.copy_from_slice(&src.octets()[..8]);

    timer_map
        .update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
        .expect("failed to insert v3 v6 ct entry");
}

fn lookup_ct6_entry<T: MapCore>(timer_map: &T, key: &Nat6TimerKey) -> Nat6TimerValue {
    let bytes = timer_map
        .lookup(key.as_bytes(), MapFlags::ANY)
        .expect("lookup ct entry")
        .expect("missing ct entry");
    Nat6TimerValue::read_from_bytes(&bytes).unwrap()
}

fn set_ct6_status<T: MapCore>(timer_map: &T, key: &Nat6TimerKey, status: u64) {
    let mut value = lookup_ct6_entry(timer_map, key);
    value.status = status;
    timer_map
        .update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
        .expect("failed to update v6 ct status");
}

fn assert_egress_ct_status_transition(initial_status: u64, expected_status: u64, verdict: i32) {
    let src = lan_host();
    let dst = remote();
    let prefix_len = 60;
    let key = timer_key_for(src, CLIENT_PORT, prefix_len, dst, 443);

    let mut builder = TcNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-v3");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
    }
    let skel = open_skel.load().unwrap();
    add_ct6_entry(&skel.maps.nat6_timer_map, &key, src);
    set_ct6_status(&skel.maps.nat6_timer_map, &key, initial_status);

    let pkt = build_ipv6_tcp(src, dst, CLIENT_PORT, 443);
    let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
    let mut packet_out = vec![0u8; pkt.len()];
    let input = ProgramInput {
        data_in: Some(&pkt),
        context_in: Some(ctx.as_mut_bytes()),
        data_out: Some(&mut packet_out),
        ..Default::default()
    };

    let result = skel.progs.tc_nat_wan_egress_v6.test_run(input).expect("test_run failed");
    assert_eq!(result.return_value as i32, verdict);
    assert_eq!(lookup_ct6_entry(&skel.maps.nat6_timer_map, &key).status, expected_status);
}

fn assert_dynamic_translation(src: Ipv6Addr, dst: Ipv6Addr, prefix_len: u8) {
    let key = timer_key_for(src, CLIENT_PORT, prefix_len, dst, 443);

    let mut builder = TcNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-v3");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
    }
    let skel = open_skel.load().unwrap();
    add_ct6_entry(&skel.maps.nat6_timer_map, &key, src);

    let pkt = build_ipv6_tcp(src, dst, CLIENT_PORT, 443);
    let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
    let mut packet_out = vec![0u8; pkt.len()];
    let input = ProgramInput {
        data_in: Some(&pkt),
        context_in: Some(ctx.as_mut_bytes()),
        data_out: Some(&mut packet_out),
        ..Default::default()
    };

    let result = skel.progs.tc_nat_wan_egress_v6.test_run(input).expect("test_run failed");
    assert_eq!(result.return_value as i32, -1, "egress should return TC_ACT_UNSPEC(-1)");

    let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
    if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
        let translated_src: Ipv6Addr = ipv6.source.into();
        assert_eq!(
            &translated_src.octets()[..8],
            &PREFIX60_WAN_NPT_PREFIX,
            "src prefix should be NPT-translated to WAN prefix",
        );
        assert_eq!(
            &translated_src.octets()[8..],
            &src.octets()[8..],
            "src suffix should be preserved",
        );
    } else {
        panic!("expected IPv6 header in output");
    }
    if let Some(etherparse::TransportHeader::Tcp(tcp)) = pkt_out.transport {
        assert_eq!(tcp.source_port, CLIENT_PORT, "src_port should be unchanged");
    } else {
        panic!("expected TCP transport header in output");
    }
}

fn assert_prefix_refresh(old_src: Ipv6Addr, new_src: Ipv6Addr, prefix_len: u8) {
    let old_remote = Ipv6Addr::from_str("2001:db8:2::1").unwrap();

    let old_key = timer_key_for(old_src, CLIENT_PORT, prefix_len, old_remote, 443);
    let new_key = timer_key_for(new_src, CLIENT_PORT, prefix_len, old_remote, 443);
    assert_eq!(old_key, new_key, "test setup must keep the same dynamic NAT key",);

    let mut builder = TcNat6SkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-v3");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = builder.open(&mut open_object).unwrap();
    {
        let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
    }
    let skel = open_skel.load().unwrap();
    add_ct6_entry(&skel.maps.nat6_timer_map, &old_key, old_src);

    let pkt = build_ipv6_tcp(new_src, old_remote, CLIENT_PORT, 443);
    let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
    let mut packet_out = vec![0u8; pkt.len()];
    let input = ProgramInput {
        data_in: Some(&pkt),
        context_in: Some(ctx.as_mut_bytes()),
        data_out: Some(&mut packet_out),
        ..Default::default()
    };

    let result = skel.progs.tc_nat_wan_egress_v6.test_run(input).expect("test_run failed");
    assert_eq!(result.return_value as i32, -1, "egress should return TC_ACT_UNSPEC(-1)");

    let value = lookup_ct6_entry(&skel.maps.nat6_timer_map, &new_key);
    assert_eq!(
        &value.client_prefix,
        &new_src.octets()[..8],
        "existing CT should refresh stored client prefix when delegated prefix changes",
    );
}

fn build_quoted_ipv6_tcp(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    build_ipv6_tcp(src, dst, src_port, dst_port)[14..].to_vec()
}

fn build_ipv6_icmp_time_exceeded(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    quoted_ipv6_packet: &[u8],
) -> Vec<u8> {
    let icmp6_type = Icmpv6Type::TimeExceeded(icmpv6::TimeExceededCode::HopLimitExceeded);
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    )
    .ipv6(src.octets(), dst.octets(), 64)
    .icmpv6(icmp6_type);

    let mut buf = Vec::with_capacity(builder.size(quoted_ipv6_packet.len()));
    builder.write(&mut buf, quoted_ipv6_packet).unwrap();
    buf
}

fn parse_inner_ipv6_from_icmpv6(packet: &[u8]) -> PacketHeaders<'_> {
    let outer = PacketHeaders::from_ethernet_slice(packet).expect("parse outer packet");
    if let Some(etherparse::NetHeaders::Ipv6(..)) = outer.net {
    } else {
        panic!("expected outer IPv6 header");
    }
    let inner_offset = 14 + 40 + 8;
    PacketHeaders::from_ip_slice(&packet[inner_offset..]).expect("parse quoted packet")
}

fn npt_wan_ip_for(lan_ip: Ipv6Addr) -> Ipv6Addr {
    let mut octets = lan_ip.octets();
    octets[..8].copy_from_slice(&PREFIX60_WAN_NPT_PREFIX);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_egress_dynamic_v3_rewrites_src_prefix() {
        assert_dynamic_translation(lan_host(), remote(), 60);
    }

    #[test]
    fn tcp_egress_reactivates_wait_timeout() {
        assert_egress_ct_status_transition(TIMER_WAIT_TIMEOUT, TIMER_ACTIVE, -1);
    }

    #[test]
    fn tcp_egress_drops_packets_in_cleanup() {
        assert_egress_ct_status_transition(TIMER_CLEAN_START, TIMER_CLEAN_START, 2);
    }

    #[test]
    fn tcp_egress_dynamic_v3_refreshes_ct_when_prefix56_changes() {
        let old_src = Ipv6Addr::from_str("fd00:1234:5678:abc5::200").unwrap();
        let new_src = Ipv6Addr::from_str("fd00:1234:5678:acc5::200").unwrap();
        assert_prefix_refresh(old_src, new_src, 56);
    }

    #[test]
    fn tcp_egress_dynamic_v3_refreshes_ct_when_prefix60_changes() {
        let old_src = Ipv6Addr::from_str("fd00:1234:5678:abc5::200").unwrap();
        let new_src = Ipv6Addr::from_str("fd00:1234:5678:abd5::200").unwrap();
        assert_prefix_refresh(old_src, new_src, 60);
    }

    #[test]
    fn icmpv6_echo_round_trip_dynamic_v3() {
        let src = lan_host();
        let dst = remote();
        let id = 0x1234;
        let prefix_len = 60;

        let mut builder = TcNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-echo");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
        }
        let skel = open_skel.load().unwrap();

        let request = build_ipv6_icmpv6_echo(src, dst, id, true);
        let mut out = vec![0u8; request.len()];
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let result = skel
            .progs
            .tc_nat_wan_egress_v6
            .test_run(ProgramInput {
                data_in: Some(&request),
                context_in: Some(ctx.as_mut_bytes()),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect("egress test_run failed");
        assert_eq!(result.return_value as i32, -1);

        let translated = npt_wan_ip_for(src);
        let parsed = PacketHeaders::from_ethernet_slice(&out).expect("parse egress output");
        let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
            panic!("expected IPv6 egress output");
        };
        assert_eq!(Ipv6Addr::from(ipv6.source), translated);

        let reply = build_ipv6_icmpv6_echo(dst, translated, id, false);
        let mut out = vec![0u8; reply.len()];
        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let result = skel
            .progs
            .tc_nat_wan_ingress_v6
            .test_run(ProgramInput {
                data_in: Some(&reply),
                context_in: Some(ctx.as_mut_bytes()),
                data_out: Some(&mut out),
                ..Default::default()
            })
            .expect("ingress test_run failed");
        assert_eq!(result.return_value as i32, 0);

        let parsed = PacketHeaders::from_ethernet_slice(&out).expect("parse ingress output");
        let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = parsed.net else {
            panic!("expected IPv6 ingress output");
        };
        assert_eq!(Ipv6Addr::from(ipv6.destination), src);
    }

    #[test]
    fn tcp_egress_dynamic_v3_icmp_error_ipv6() {
        let src = lan_host();
        let dst = remote();
        let prefix_len = 60;

        // Real TCP connections live in nat6_timer_map under inner l4_protocol = TCP (6),
        // not NEXTHDR_ICMP (58).
        let key = timer_key_for(src, CLIENT_PORT, prefix_len, dst, 443);

        let mut builder = TcNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-v3");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
        }
        let skel = open_skel.load().unwrap();
        add_ct6_entry(&skel.maps.nat6_timer_map, &key, src);

        let quoted = build_quoted_ipv6_tcp(dst, src, 443, CLIENT_PORT);
        let pkt = build_ipv6_icmp_time_exceeded(src, dst, &quoted);

        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_egress_v6.test_run(input).expect("test_run failed");
        assert_eq!(
            result.return_value as i32, -1,
            "egress ICMP error should return TC_ACT_UNSPEC(-1)"
        );

        let ct_after = lookup_ct6_entry(&skel.maps.nat6_timer_map, &key);
        assert_eq!(ct_after.tcp_flags, TCP_BOTH_SYN, "ICMPv6 error must preserve the handshake");

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let translated_src: Ipv6Addr = ipv6.source.into();
            assert_eq!(
                &translated_src.octets()[..8],
                &PREFIX60_WAN_NPT_PREFIX,
                "outer src prefix should be NPT-translated to WAN prefix",
            );
            assert_eq!(
                &translated_src.octets()[8..],
                &src.octets()[8..],
                "outer src suffix should be preserved",
            );
        } else {
            panic!("expected IPv6 header in output");
        }

        let quoted_out = parse_inner_ipv6_from_icmpv6(&packet_out);
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = quoted_out.net {
            let translated_dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(
                &translated_dst.octets()[..8],
                &PREFIX60_WAN_NPT_PREFIX,
                "inner dst prefix should be NPT-translated to WAN prefix",
            );
        } else {
            panic!("expected quoted IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = quoted_out.transport {
            assert_eq!(tcp.destination_port, CLIENT_PORT, "inner dst port should be unchanged");
        }
    }

    #[test]
    fn tcp_ingress_dynamic_v3_icmp_error_ipv6() {
        let src = lan_host();
        let dst = remote();
        let wan_src = npt_wan_ip_for(src);
        let prefix_len = 60;

        // Real TCP connections live in nat6_timer_map under inner l4_protocol = TCP (6),
        // not NEXTHDR_ICMP (58).
        let key = timer_key_for(src, CLIENT_PORT, prefix_len, dst, 443);

        let mut builder = TcNat6SkelBuilder::default();
        let pin_root = crate::tests::isolated_pin_root("nat-v6-dynamic-v3");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
            rodata.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(prefix_len);
        }
        let skel = open_skel.load().unwrap();
        add_ct6_entry(&skel.maps.nat6_timer_map, &key, src);

        let quoted = build_quoted_ipv6_tcp(wan_src, dst, CLIENT_PORT, 443);
        let pkt = build_ipv6_icmp_time_exceeded(dst, wan_src, &quoted);

        let mut ctx = TestSkb { ifindex: IFINDEX, ..Default::default() };
        let mut packet_out = vec![0u8; pkt.len()];
        let input = ProgramInput {
            data_in: Some(&pkt),
            context_in: Some(ctx.as_mut_bytes()),
            data_out: Some(&mut packet_out),
            ..Default::default()
        };

        let result = skel.progs.tc_nat_wan_ingress_v6.test_run(input).expect("test_run failed");
        assert_eq!(result.return_value as i32, 0, "ingress ICMP error should return TC_ACT_OK(0)");

        let ct_after = lookup_ct6_entry(&skel.maps.nat6_timer_map, &key);
        assert_eq!(ct_after.tcp_flags, TCP_BOTH_SYN, "ICMPv6 error must preserve the handshake");

        let pkt_out = PacketHeaders::from_ethernet_slice(&packet_out).expect("parse output");
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = pkt_out.net {
            let translated_dst: Ipv6Addr = ipv6.destination.into();
            assert_eq!(
                &translated_dst.octets()[..8],
                &src.octets()[..8],
                "outer dst prefix should be reverse-translated to LAN prefix",
            );
            assert_eq!(
                &translated_dst.octets()[8..],
                &src.octets()[8..],
                "outer dst suffix should be preserved",
            );
        } else {
            panic!("expected IPv6 header in output");
        }

        let quoted_out = parse_inner_ipv6_from_icmpv6(&packet_out);
        if let Some(etherparse::NetHeaders::Ipv6(ipv6, _)) = quoted_out.net {
            let translated_src: Ipv6Addr = ipv6.source.into();
            assert_eq!(
                &translated_src.octets()[..8],
                &src.octets()[..8],
                "inner src prefix should be reverse-translated to LAN prefix",
            );
        } else {
            panic!("expected quoted IPv6 header in output");
        }
        if let Some(etherparse::TransportHeader::Tcp(tcp)) = quoted_out.transport {
            assert_eq!(tcp.source_port, CLIENT_PORT, "inner src port should be unchanged");
        }
    }

    #[test]
    fn only_trigger_packets_update_endpoint_reuse_after_prefix_change() {
        let old_src = lan_host();
        let new_src = "fd00:1234:5678:abd5::200".parse().unwrap();
        let peer = remote();
        let first = timer_key_for(old_src, CLIENT_PORT, 60, peer, 443);
        let second = timer_key_for(old_src, CLIENT_PORT, 60, peer, 8443);
        let mut builder = TcNat6SkelBuilder::default();
        let root = crate::tests::isolated_pin_root("nat6-mapping-refresh");
        builder.object_builder_mut().pin_root_path(&root).unwrap();
        let mut obj = MaybeUninit::uninit();
        let mut open = builder.open(&mut obj).unwrap();
        let ro = open.maps.rodata_data.as_deref_mut().unwrap();
        ro.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        ro.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
        let skel = open.load().unwrap();
        let mapping = &skel.maps.nat6_mapping_map;
        let read = || {
            Nat6MappingValue::read_from_bytes(
                &mapping.lookup(first.local.as_bytes(), MapFlags::ANY).unwrap().unwrap(),
            )
            .unwrap()
        };
        let send = |src: Ipv6Addr, port, mark, syn| {
            let mut frame = Vec::new();
            let tcp = PacketBuilder::ethernet2([2; 6], [4; 6])
                .ipv6(src.octets(), peer.octets(), 64)
                .tcp(CLIENT_PORT, port, 1, 4096);
            if syn { tcp.syn() } else { tcp.ack(1) }.write(&mut frame, &[]).unwrap();
            let mut ctx = TestSkb { ifindex: IFINDEX, mark, ..Default::default() };
            skel.progs
                .tc_nat_wan_egress_v6
                .test_run(ProgramInput {
                    data_in: Some(&frame),
                    context_in: Some(ctx.as_mut_bytes()),
                    ..Default::default()
                })
                .unwrap()
                .return_value as i32
        };

        assert_eq!(send(old_src, 443, 0, true), -1);
        assert_eq!(send(old_src, 8443, 0x8000, true), 2);
        assert_eq!(read().refs, 1);
        assert_eq!(send(new_src, 443, 0x8000, false), -1);
        assert_eq!(read().allow_reuse, 1);
        assert_eq!(send(old_src, 8443, 0, true), -1);
        assert_eq!(send(new_src, 8443, 0, false), -1);
        let shared = read();
        assert_eq!(shared.allow_reuse, 1);
        assert_eq!(shared.client_prefix, new_src.octets()[..8]);
        assert_eq!((shared.trigger_addr, shared.trigger_port), (peer.octets(), 443u16.to_be()));
        assert_eq!(shared.refs, 2);
        assert_eq!(send(new_src, 443, 0, false), -1);
        assert_eq!(read().allow_reuse, 0);
        assert_eq!(send(new_src, 8443, 0, false), -1);
        assert_eq!(send(new_src, 9443, 0x8000, true), 2);
        assert_eq!(lookup_ct6_entry(&skel.maps.nat6_timer_map, &first).egress_packets, 3);
        assert_eq!(lookup_ct6_entry(&skel.maps.nat6_timer_map, &second).egress_packets, 3);
    }
    #[test]
    fn skip_route_mark_does_not_leak_chain_id_into_nat6_ct() {
        let src = lan_host();
        let peer = remote();
        let key = timer_key_for(src, CLIENT_PORT, 60, peer, 443);

        let mut builder = TcNat6SkelBuilder::default();
        let root = crate::tests::isolated_pin_root("nat6-skip-route-mark");
        builder.object_builder_mut().pin_root_path(&root).unwrap();
        let mut obj = MaybeUninit::uninit();
        let mut open = builder.open(&mut obj).unwrap();
        let ro = open.maps.rodata_data.as_deref_mut().unwrap();
        ro.wan_ro_prefix6.b = crate::stages::nat6::wan_ro_prefix6(Some(wan_ip()));
        ro.wan_ro_npt_mask = crate::maps::wan::compute_npt_mask(60);
        let skel = open.load().unwrap();

        let mut frame = Vec::new();
        PacketBuilder::ethernet2([2; 6], [4; 6])
            .ipv6(src.octets(), peer.octets(), 64)
            .tcp(CLIENT_PORT, 443, 1, 4096)
            .syn()
            .write(&mut frame, &[])
            .unwrap();

        let mut ctx = TestSkb {
            ifindex: IFINDEX,
            mark: crate::tests::helper::map::skip_route_mark(0x8003),
            ..Default::default()
        };
        let ret = skel
            .progs
            .tc_nat_wan_egress_v6
            .test_run(ProgramInput {
                data_in: Some(&frame),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .unwrap()
            .return_value as i32;
        assert_eq!(ret, -1);

        let ct = lookup_ct6_entry(&skel.maps.nat6_timer_map, &key);
        assert_eq!(ct.flow_id, 0, "chain id must not become a NAT6 flow id");
        assert_eq!(ct.allow_reuse, 0, "chain id must not set allow_reuse");
    }
}
