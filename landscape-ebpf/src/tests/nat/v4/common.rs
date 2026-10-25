//! Shared helpers for the migrated NAT4-v4 test suites.
//!
//! These mirror the helpers in `tc_nat4_v4_behavior.rs` but use the generated
//! map types instead of raw byte slices, so the older v3 scenarios can be
//! ported without keeping the deleted v3 map layouts around.

#![allow(dead_code)]

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use etherparse::{
    IcmpEchoHeader, Icmpv4Type, IpFragOffset, IpHeaders, IpNumber, Ipv4Extensions, Ipv4Header,
    PacketBuilder, PacketHeaders, TransportHeader, icmpv4,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::tests::TestSkb;
use crate::tests::helper::map::as_bytes;
use crate::tests::tc_nat4_v4_skel::{TcNat4V4Skel, TcNat4V4SkelBuilder, types};

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;

pub(crate) const KIND_FREE: u8 = 0;
pub(crate) const KIND_DYNAMIC: u8 = 1;
pub(crate) const KIND_STATIC: u8 = 2;

pub(crate) const STATE_ACTIVE: u64 = 1;
pub(crate) const STATE_SHIFT: u64 = 56;
pub(crate) const CT_ACTIVE: u64 = 20;

pub(crate) const NAPT_FROM_WAN_TCP_BASE: u32 = 65536;
pub(crate) const NAPT_FROM_WAN_ICMP_BASE: u32 = 131072;

pub(crate) const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
pub(crate) const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
pub(crate) const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub(crate) const LAN_PORT: u16 = 12345;
pub(crate) const REMOTE_PORT: u16 = 53;
pub(crate) const IFINDEX: u32 = 6;

const MAC_SRC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const MAC_DST: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

pub(crate) fn wan_ro_addr4(addr: Ipv4Addr) -> u32 {
    addr.to_bits().to_be()
}

pub(crate) fn be32(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

pub(crate) fn state_ref(state: u64, refs: u64) -> u64 {
    (state << STATE_SHIFT) | refs
}

pub(crate) fn with_skel<R>(
    udp_ports: &[u16],
    tcp_ports: &[u16],
    icmp_ids: &[u16],
    f: impl FnOnce(&TcNat4V4Skel<'_>) -> R,
) -> R {
    with_skel_wan(WAN_IP, udp_ports, tcp_ports, icmp_ids, f)
}

pub(crate) fn with_skel_wan<R>(
    wan_addr: Ipv4Addr,
    udp_ports: &[u16],
    tcp_ports: &[u16],
    icmp_ids: &[u16],
    f: impl FnOnce(&TcNat4V4Skel<'_>) -> R,
) -> R {
    let builder = TcNat4V4SkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = 14;
        rodata.land_nat_external_addr = wan_ro_addr4(wan_addr);
        rodata.land_nat_udp_range_start = 32768;
        rodata.land_nat_udp_range_end = 65535;
        rodata.land_nat_tcp_range_start = 32768;
        rodata.land_nat_tcp_range_end = 65535;
    }
    let skel = open.load().unwrap();

    for &port in udp_ports {
        queue_push(&skel.maps.napt_udp_ports, port, 0);
    }
    for &port in tcp_ports {
        queue_push(&skel.maps.napt_tcp_ports, port, 0);
    }
    for &id in icmp_ids {
        queue_push(&skel.maps.napt_icmp_ids, id, 0);
    }

    f(&skel)
}

pub(crate) fn queue_push(map: &impl MapCore, port: u16, generation: u32) {
    let mut value = [0u8; 8];
    value[0..2].copy_from_slice(&port.to_be_bytes());
    value[4..8].copy_from_slice(&generation.to_ne_bytes());
    let ret = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map.as_fd().as_raw_fd(),
            std::ptr::null(),
            value.as_ptr().cast(),
            0,
        )
    };
    assert_eq!(ret, 0, "queue push failed");
}

pub(crate) fn run(prog: &ProgramMut<'_>, pkt: &[u8]) -> (i32, Vec<u8>) {
    run_with_ifindex(prog, pkt, IFINDEX)
}

pub(crate) fn run_with_ifindex(prog: &ProgramMut<'_>, pkt: &[u8], ifindex: u32) -> (i32, Vec<u8>) {
    let mut out = vec![0u8; pkt.len()];
    let mut ctx = TestSkb { ifindex, ..Default::default() };
    let input = ProgramInput {
        data_in: Some(pkt),
        context_in: Some(ctx.as_mut_bytes()),
        data_out: Some(&mut out),
        ..Default::default()
    };
    let ret = prog.test_run(input).expect("test_run failed").return_value as i32;
    (ret, out)
}

pub(crate) fn udp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

pub(crate) fn tcp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, syn: bool) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1234_5678, 4096);
    let builder = if syn { builder.syn() } else { builder.ack(1) };
    let payload = [0u8; 0];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

pub(crate) fn icmp_pkt(src: Ipv4Addr, dst: Ipv4Addr, id: u16, request: bool) -> Vec<u8> {
    let echo = IcmpEchoHeader { id, seq: 1 };
    let ty = if request { Icmpv4Type::EchoRequest(echo) } else { Icmpv4Type::EchoReply(echo) };
    let builder =
        PacketBuilder::ethernet2(MAC_SRC, MAC_DST).ipv4(src.octets(), dst.octets(), 64).icmpv4(ty);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

pub(crate) fn ipv4_frag_udp(first: bool, id: u16) -> Vec<u8> {
    let l4 = if first {
        let payload = [0x11_u8, 0x22, 0x33, 0x44];
        let mut bytes = Vec::with_capacity(8 + payload.len());
        bytes.extend_from_slice(&LAN_PORT.to_be_bytes());
        bytes.extend_from_slice(&REMOTE_PORT.to_be_bytes());
        bytes.extend_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&payload);
        bytes
    } else {
        vec![0xAB_u8; 32]
    };

    let mut ipv4 =
        Ipv4Header::new(0u16, 64, IpNumber::UDP, LAN_HOST.octets(), REMOTE_IP.octets()).unwrap();
    ipv4.identification = id;
    ipv4.more_fragments = true;
    ipv4.fragment_offset = IpFragOffset::try_new(if first { 0 } else { 1 }).unwrap();
    ipv4.set_payload_len(l4.len()).unwrap();
    ipv4.header_checksum = ipv4.calc_header_checksum();

    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ip(IpHeaders::Ipv4(ipv4, Ipv4Extensions::default()));
    let mut pkt = Vec::with_capacity(builder.size(l4.len()));
    builder.write(&mut pkt, IpNumber::UDP, &l4).unwrap();
    pkt
}

pub(crate) fn icmp_error_tcp_min(
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_sport: u16,
    inner_dport: u16,
    outer_src: Ipv4Addr,
    outer_dst: Ipv4Addr,
) -> Vec<u8> {
    let inner = PacketBuilder::ipv4(inner_src.octets(), inner_dst.octets(), 64).tcp(
        inner_sport,
        inner_dport,
        0x1234_5678,
        65535,
    );
    let mut inner_bytes = Vec::with_capacity(inner.size(0));
    inner.write(&mut inner_bytes, &[]).unwrap();
    let quoted = &inner_bytes[..20 + 8];

    let outer = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(outer_src.octets(), outer_dst.octets(), 64)
        .icmpv4(Icmpv4Type::TimeExceeded(icmpv4::TimeExceededCode::TtlExceededInTransit));
    let mut pkt = Vec::with_capacity(outer.size(quoted.len()));
    outer.write(&mut pkt, quoted).unwrap();
    pkt
}

pub(crate) fn icmp_error_wan(
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_sport: u16,
    inner_dport: u16,
    outer_src: Ipv4Addr,
    outer_dst: Ipv4Addr,
) -> Vec<u8> {
    let inner = PacketBuilder::ipv4(inner_src.octets(), inner_dst.octets(), 64)
        .udp(inner_sport, inner_dport);
    let payload = [0u8; 8];
    let mut inner_bytes = Vec::with_capacity(inner.size(payload.len()));
    inner.write(&mut inner_bytes, &payload).unwrap();
    let quoted = &inner_bytes[..20 + 8];

    let outer = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(outer_src.octets(), outer_dst.octets(), 64)
        .icmpv4(Icmpv4Type::TimeExceeded(icmpv4::TimeExceededCode::TtlExceededInTransit));
    let mut pkt = Vec::with_capacity(outer.size(quoted.len()));
    outer.write(&mut pkt, quoted).unwrap();
    pkt
}

pub(crate) fn parse_ipv4_dst(pkt: &[u8]) -> Ipv4Addr {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.net {
        Some(etherparse::NetHeaders::Ipv4(ip, _)) => ip.destination.into(),
        _ => panic!("expected IPv4"),
    }
}

pub(crate) fn parse_ipv4_src(pkt: &[u8]) -> Ipv4Addr {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.net {
        Some(etherparse::NetHeaders::Ipv4(ip, _)) => ip.source.into(),
        _ => panic!("expected IPv4"),
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct UdpOut {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
}

pub(crate) fn parse_udp(pkt: &[u8]) -> UdpOut {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    let (src, dst) = match parsed.net {
        Some(etherparse::NetHeaders::Ipv4(ip, _)) => (ip.source.into(), ip.destination.into()),
        _ => panic!("expected IPv4"),
    };
    let (sport, dport) = match parsed.transport {
        Some(TransportHeader::Udp(udp)) => (udp.source_port, udp.destination_port),
        _ => panic!("expected UDP"),
    };
    UdpOut { src, dst, sport, dport }
}

pub(crate) fn parse_tcp_ports(pkt: &[u8]) -> (u16, u16) {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.transport {
        Some(TransportHeader::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
        _ => panic!("expected TCP"),
    }
}

pub(crate) fn parse_icmp_dst_id(pkt: &[u8]) -> (Ipv4Addr, u16) {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    let dst = match parsed.net {
        Some(etherparse::NetHeaders::Ipv4(ip, _)) => ip.destination.into(),
        _ => panic!("expected IPv4"),
    };
    let id = match parsed.transport {
        Some(TransportHeader::Icmpv4(icmp)) => match icmp.icmp_type {
            Icmpv4Type::EchoRequest(echo) | Icmpv4Type::EchoReply(echo) => echo.id,
            _ => panic!("expected echo"),
        },
        _ => panic!("expected ICMPv4"),
    };
    (dst, id)
}

pub(crate) fn from_lan_key(
    internal_addr: Ipv4Addr,
    internal_port: u16,
    proto: u8,
) -> types::napt_from_lan_key {
    types::napt_from_lan_key {
        internal_addr: be32(internal_addr),
        internal_port: internal_port.to_be(),
        proto,
        pad: 0,
    }
}

pub(crate) fn from_wan_index(proto: u8, external_port: u16) -> u32 {
    let base = match proto {
        PROTO_UDP => 0,
        PROTO_TCP => NAPT_FROM_WAN_TCP_BASE,
        PROTO_ICMP => NAPT_FROM_WAN_ICMP_BASE,
        _ => panic!("bad proto"),
    };
    base + external_port as u32
}

pub(crate) fn ct_key(
    internal_addr: Ipv4Addr,
    internal_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    proto: u8,
) -> types::napt_ct_key {
    types::napt_ct_key {
        internal_addr: be32(internal_addr),
        remote_addr: be32(remote_addr),
        internal_port: internal_port.to_be(),
        remote_port: remote_port.to_be(),
        proto,
        pad: [0; 3],
    }
}

pub(crate) fn seed_static(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
) {
    let lan = types::napt_from_lan_value {
        external_port: external_port.to_be(),
        kind: KIND_STATIC,
        allow_reuse: 1,
        generation: 0,
        trigger_addr: 0,
        trigger_port: 0,
        pad: 0,
    };
    skel.maps
        .napt_from_lan
        .update(
            as_bytes(&from_lan_key(internal_addr, internal_port, proto)),
            as_bytes(&lan),
            MapFlags::ANY,
        )
        .unwrap();

    let wan = types::napt_from_wan_value {
        internal_addr: be32(internal_addr),
        internal_port: internal_port.to_be(),
        kind: KIND_STATIC,
        allow_reuse: 1,
        trigger_addr: 0,
        trigger_port: 0,
        pad0: 0,
        generation: 0,
        pad1: 0,
        state_ref: state_ref(STATE_ACTIVE, 0),
    };
    skel.maps
        .napt_from_wan
        .update(&from_wan_index(proto, external_port).to_ne_bytes(), as_bytes(&wan), MapFlags::ANY)
        .unwrap();
}

pub(crate) fn seed_static_ct(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) {
    let value = types::napt_ct_value {
        external_port: external_port.to_be(),
        is_static: 1,
        pad0: 0,
        from_wan_gen: 0,
        status: CT_ACTIVE,
        client_status: 0,
        server_status: 0,
        ..Default::default()
    };
    skel.maps
        .napt_ct
        .update(
            as_bytes(&ct_key(internal_addr, internal_port, remote_addr, remote_port, proto)),
            as_bytes(&value),
            MapFlags::ANY,
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn seed_dynamic(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    allow_reuse: u8,
    generation: u32,
    refs: u64,
) {
    let lan = types::napt_from_lan_value {
        external_port: external_port.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse,
        generation,
        trigger_addr: be32(remote_addr),
        trigger_port: remote_port.to_be(),
        pad: 0,
    };
    skel.maps
        .napt_from_lan
        .update(
            as_bytes(&from_lan_key(internal_addr, internal_port, proto)),
            as_bytes(&lan),
            MapFlags::ANY,
        )
        .unwrap();

    let wan = types::napt_from_wan_value {
        internal_addr: be32(internal_addr),
        internal_port: internal_port.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse,
        trigger_addr: be32(remote_addr),
        trigger_port: remote_port.to_be(),
        pad0: 0,
        generation,
        pad1: 0,
        state_ref: state_ref(STATE_ACTIVE, refs),
    };
    skel.maps
        .napt_from_wan
        .update(&from_wan_index(proto, external_port).to_ne_bytes(), as_bytes(&wan), MapFlags::ANY)
        .unwrap();
}

pub(crate) fn seed_dynamic_ct(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    generation: u32,
    status: u64,
) {
    let value = types::napt_ct_value {
        external_port: external_port.to_be(),
        is_static: 0,
        pad0: 0,
        from_wan_gen: generation,
        status,
        client_status: 0,
        server_status: 0,
        ..Default::default()
    };
    skel.maps
        .napt_ct
        .update(
            as_bytes(&ct_key(internal_addr, internal_port, remote_addr, remote_port, proto)),
            as_bytes(&value),
            MapFlags::ANY,
        )
        .unwrap();
}
