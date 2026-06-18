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
    map_setting::add_wan_ip,
    stages::nat::tc_nat_skel::{types, TcNatSkelBuilder},
    tests::TestSkb,
};

const IFINDEX: u32 = 6;
const L4PROTO_TCP: u8 = 6;
const CLIENT_PORT: u16 = 12345;
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

fn npt_id_mask(prefix_len: u8) -> u8 {
    if prefix_len >= 64 {
        0
    } else {
        ((1u16 << (64 - prefix_len)) - 1) as u8
    }
}

fn timer_key_for(src: Ipv6Addr, client_port: u16, prefix_len: u8) -> types::nat_timer_key_v6 {
    let bytes = src.octets();
    let mut client_suffix = [0u8; 8];
    client_suffix.copy_from_slice(&bytes[8..]);

    types::nat_timer_key_v6 {
        client_suffix,
        client_port: client_port.to_be(),
        id_byte: bytes[7] & npt_id_mask(prefix_len),
        l4_protocol: L4PROTO_TCP,
    }
}

fn add_ct6_entry<T: MapCore>(
    timer_map: &T,
    key: &types::nat_timer_key_v6,
    src: Ipv6Addr,
    trigger_addr: Ipv6Addr,
    trigger_port: u16,
) {
    let mut value = types::nat_timer_value_v6 {
        server_status: 1,
        client_status: 1,
        is_allow_reuse: 1,
        ..Default::default()
    };
    value.trigger_addr = types::u_inet6_addr { bytes: trigger_addr.octets() };
    value.trigger_port = trigger_port.to_be();
    value.client_prefix.copy_from_slice(&src.octets()[..8]);

    timer_map
        .update(unsafe { plain::as_bytes(key) }, unsafe { plain::as_bytes(&value) }, MapFlags::ANY)
        .expect("failed to insert v3 v6 ct entry");
}

fn lookup_ct6_entry<T: MapCore>(
    timer_map: &T,
    key: &types::nat_timer_key_v6,
) -> types::nat_timer_value_v6 {
    let bytes = timer_map
        .lookup(unsafe { plain::as_bytes(key) }, MapFlags::ANY)
        .expect("lookup ct entry")
        .expect("missing ct entry");
    unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<types::nat_timer_value_v6>()) }
}

fn assert_dynamic_translation(src: Ipv6Addr, dst: Ipv6Addr, prefix_len: u8) {
    let key = timer_key_for(src, CLIENT_PORT, prefix_len);

    let mut builder = TcNatSkelBuilder::default();
    let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-dynamic-v3");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();

    add_wan_ip(
        &skel.maps.wan_ip_binding,
        IFINDEX,
        IpAddr::V6(wan_ip()),
        None,
        prefix_len,
        Some(MacAddr::broadcast()),
    );
    add_ct6_entry(&skel.maps.nat6_conn_timer, &key, src, dst, 443);

    let mut pkt = build_ipv6_tcp(src, dst, CLIENT_PORT, 443);
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
    let new_remote = Ipv6Addr::from_str("2001:db8:2::2").unwrap();

    let old_key = timer_key_for(old_src, CLIENT_PORT, prefix_len);
    let new_key = timer_key_for(new_src, CLIENT_PORT, prefix_len);
    assert_eq!(
        unsafe { plain::as_bytes(&old_key) },
        unsafe { plain::as_bytes(&new_key) },
        "test setup must keep the same dynamic NAT key",
    );

    let mut builder = TcNatSkelBuilder::default();
    let pin_root = crate::tests::nat::isolated_pin_root("nat-v6-dynamic-v3");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();

    add_wan_ip(
        &skel.maps.wan_ip_binding,
        IFINDEX,
        IpAddr::V6(wan_ip()),
        None,
        prefix_len,
        Some(MacAddr::broadcast()),
    );
    add_ct6_entry(&skel.maps.nat6_conn_timer, &old_key, old_src, old_remote, 443);

    let mut pkt = build_ipv6_tcp(new_src, new_remote, CLIENT_PORT, 8443);
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

    let value = lookup_ct6_entry(&skel.maps.nat6_conn_timer, &new_key);
    assert_eq!(
        &value.client_prefix,
        &new_src.octets()[..8],
        "existing CT should refresh stored client prefix when delegated prefix changes",
    );
    assert_eq!(
        unsafe { value.trigger_addr.bytes },
        new_remote.octets(),
        "existing CT should refresh trigger_addr on prefix refresh",
    );
    assert_eq!(
        value.trigger_port,
        8443u16.to_be(),
        "existing CT should refresh trigger_port on prefix refresh",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_egress_dynamic_v3_rewrites_src_prefix() {
        assert_dynamic_translation(lan_host(), remote(), 60);
    }

    #[test]
    fn tcp_egress_dynamic_v3_refreshes_ct_when_prefix60_changes() {
        let old_src = Ipv6Addr::from_str("fd00:1234:5678:abc5::200").unwrap();
        let new_src = Ipv6Addr::from_str("fd00:1234:5678:abd5::200").unwrap();
        assert_prefix_refresh(old_src, new_src, 60);
    }

    #[test]
    fn tcp_egress_dynamic_v3_refreshes_ct_when_prefix56_changes() {
        let old_src = Ipv6Addr::from_str("fd00:1234:5678:abc5::200").unwrap();
        let new_src = Ipv6Addr::from_str("fd00:1234:5678:acc5::200").unwrap();
        assert_prefix_refresh(old_src, new_src, 56);
    }
}
