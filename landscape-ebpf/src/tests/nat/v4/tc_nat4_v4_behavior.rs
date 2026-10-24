use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd};

use etherparse::{
    IcmpEchoHeader, Icmpv4Type, IpFragOffset, IpHeaders, IpNumber, Ipv4Extensions, Ipv4Header,
    NetHeaders, PacketBuilder, PacketHeaders, TransportHeader, icmpv4,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::tests::tc_nat4_v4_skel::{TcNat4V4Skel, TcNat4V4SkelBuilder};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const KIND_FREE: u8 = 0;
const KIND_DYNAMIC: u8 = 1;
const KIND_STATIC: u8 = 2;

const STATE_ACTIVE: u64 = 1;
const STATE_SHIFT: u64 = 56;
const CT_ACTIVE: u64 = 20;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LAN_PORT: u16 = 12345;
const REMOTE_PORT: u16 = 53;
const TCP_REMOTE_PORT: u16 = 80;
const UDP_NAT_PORT: u16 = 40000;
const TCP_NAT_PORT: u16 = 40001;
const ICMP_INTERNAL_ID: u16 = 0x4321;
const ICMP_EXTERNAL_ID: u16 = 0x1234;

const NAPT_FROM_WAN_TCP_BASE: u32 = 65536;
const NAPT_FROM_WAN_ICMP_BASE: u32 = 131072;

const MAC_SRC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const MAC_DST: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

fn with_skel<R>(
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
        rodata.land_nat_external_addr = u32::from_ne_bytes(WAN_IP.octets());
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

fn queue_push(map: &impl MapCore, port: u16, generation: u32) {
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

fn run(prog: &ProgramMut<'_>, pkt: &[u8]) -> (i32, Vec<u8>) {
    let mut out = vec![0u8; pkt.len()];
    let input = ProgramInput {
        data_in: Some(pkt),
        data_out: Some(&mut out),
        ..Default::default()
    };
    let ret = prog.test_run(input).expect("test_run failed").return_value as i32;
    (ret, out)
}

fn udp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

fn tcp_pkt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, syn: bool) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(MAC_SRC, MAC_DST)
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, 0x1234_5678, 4096);
    let builder = if syn { builder.syn() } else { builder.ack(1) };
    let payload = [0u8; 0];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

fn icmp_pkt(src: Ipv4Addr, dst: Ipv4Addr, id: u16, request: bool) -> Vec<u8> {
    let echo = IcmpEchoHeader { id, seq: 1 };
    let ty = if request { Icmpv4Type::EchoRequest(echo) } else { Icmpv4Type::EchoReply(echo) };
    let builder =
        PacketBuilder::ethernet2(MAC_SRC, MAC_DST).ipv4(src.octets(), dst.octets(), 64).icmpv4(ty);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).unwrap();
    pkt
}

fn ipv4_frag_udp(first: bool, id: u16) -> Vec<u8> {
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

fn icmp_error_wan(
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

fn parse_ipv4_dst(pkt: &[u8]) -> Ipv4Addr {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.net {
        Some(NetHeaders::Ipv4(ip, _)) => ip.destination.into(),
        _ => panic!("expected IPv4"),
    }
}

fn parse_ipv4_src(pkt: &[u8]) -> Ipv4Addr {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.net {
        Some(NetHeaders::Ipv4(ip, _)) => ip.source.into(),
        _ => panic!("expected IPv4"),
    }
}

struct UdpOut {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
}

fn parse_udp(pkt: &[u8]) -> UdpOut {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    let (src, dst) = match parsed.net {
        Some(NetHeaders::Ipv4(ip, _)) => (ip.source.into(), ip.destination.into()),
        _ => panic!("expected IPv4"),
    };
    let (sport, dport) = match parsed.transport {
        Some(TransportHeader::Udp(udp)) => (udp.source_port, udp.destination_port),
        _ => panic!("expected UDP"),
    };
    UdpOut { src, dst, sport, dport }
}

fn parse_tcp_ports(pkt: &[u8]) -> (u16, u16) {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    match parsed.transport {
        Some(TransportHeader::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
        _ => panic!("expected TCP"),
    }
}

fn parse_icmp_dst_id(pkt: &[u8]) -> (Ipv4Addr, u16) {
    let parsed = PacketHeaders::from_ethernet_slice(pkt).expect("parse output");
    let dst = match parsed.net {
        Some(NetHeaders::Ipv4(ip, _)) => ip.destination.into(),
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

fn from_lan_key(local_addr: Ipv4Addr, local_port: u16, proto: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&local_addr.octets());
    out[4..6].copy_from_slice(&local_port.to_be_bytes());
    out[6] = proto;
    out
}

fn from_wan_index(proto: u8, external_port: u16) -> u32 {
    let base = match proto {
        PROTO_UDP => 0,
        PROTO_TCP => NAPT_FROM_WAN_TCP_BASE,
        PROTO_ICMP => NAPT_FROM_WAN_ICMP_BASE,
        _ => panic!("bad proto"),
    };
    base + external_port as u32
}

fn ct_key(
    local_addr: Ipv4Addr,
    local_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    proto: u8,
) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&local_addr.octets());
    out[4..8].copy_from_slice(&remote_addr.octets());
    out[8..10].copy_from_slice(&local_port.to_be_bytes());
    out[10..12].copy_from_slice(&remote_port.to_be_bytes());
    out[12] = proto;
    out
}

#[derive(Debug, PartialEq)]
struct LanValue {
    external_port: u16,
    kind: u8,
    generation: u32,
}

fn parse_lan_value(bytes: &[u8]) -> LanValue {
    LanValue {
        external_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        kind: bytes[2],
        generation: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
    }
}

#[derive(Debug, PartialEq)]
struct WanValue {
    internal_addr: Ipv4Addr,
    internal_port: u16,
    kind: u8,
    generation: u32,
    state_ref: u64,
}

fn parse_wan_value(bytes: &[u8]) -> WanValue {
    WanValue {
        internal_addr: Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
        internal_port: u16::from_be_bytes([bytes[4], bytes[5]]),
        kind: bytes[6],
        generation: u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
        state_ref: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
    }
}

#[derive(Debug, PartialEq)]
struct CtValue {
    external_port: u16,
    is_static: u8,
    generation: u32,
    status: u64,
}

fn parse_ct_value(bytes: &[u8]) -> CtValue {
    CtValue {
        external_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        is_static: bytes[2],
        generation: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        status: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
    }
}

fn seed_static(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
) {
    let mut lan = [0u8; 16];
    lan[0..2].copy_from_slice(&external_port.to_be_bytes());
    lan[2] = KIND_STATIC;
    lan[3] = 1;
    let lan_key = from_lan_key(internal_addr, internal_port, proto);
    skel.maps.napt_from_lan.update(&lan_key, &lan, MapFlags::ANY).unwrap();

    let mut wan = [0u8; 32];
    wan[0..4].copy_from_slice(&internal_addr.octets());
    wan[4..6].copy_from_slice(&internal_port.to_be_bytes());
    wan[6] = KIND_STATIC;
    wan[7] = 1;
    wan[24..32].copy_from_slice(&((STATE_ACTIVE << STATE_SHIFT) | 0).to_ne_bytes());
    let wan_key = from_wan_index(proto, external_port).to_ne_bytes();
    skel.maps.napt_from_wan.update(&wan_key, &wan, MapFlags::ANY).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn seed_dynamic(
    skel: &TcNat4V4Skel<'_>,
    proto: u8,
    internal_addr: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    allow_reuse: u8,
) {
    let mut lan = [0u8; 16];
    lan[0..2].copy_from_slice(&external_port.to_be_bytes());
    lan[2] = KIND_DYNAMIC;
    lan[3] = allow_reuse;
    lan[8..12].copy_from_slice(&remote_addr.octets());
    lan[12..14].copy_from_slice(&remote_port.to_be_bytes());
    let lan_key = from_lan_key(internal_addr, internal_port, proto);
    skel.maps.napt_from_lan.update(&lan_key, &lan, MapFlags::ANY).unwrap();

    let mut wan = [0u8; 32];
    wan[0..4].copy_from_slice(&internal_addr.octets());
    wan[4..6].copy_from_slice(&internal_port.to_be_bytes());
    wan[6] = KIND_DYNAMIC;
    wan[7] = allow_reuse;
    wan[8..12].copy_from_slice(&remote_addr.octets());
    wan[12..14].copy_from_slice(&remote_port.to_be_bytes());
    wan[24..32].copy_from_slice(&((STATE_ACTIVE << STATE_SHIFT) | 1).to_ne_bytes());
    let wan_key = from_wan_index(proto, external_port).to_ne_bytes();
    skel.maps.napt_from_wan.update(&wan_key, &wan, MapFlags::ANY).unwrap();
}

#[test]
fn lan_udp_create_and_wan_reverse() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let (ret, out) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);
        let out = parse_udp(&out);
        assert_eq!(out.src, WAN_IP);
        assert_eq!(out.dst, REMOTE_IP);
        assert_eq!(out.sport, UDP_NAT_PORT);
        assert_eq!(out.dport, REMOTE_PORT);

        let key = from_lan_key(LAN_HOST, LAN_PORT, PROTO_UDP);
        let val = skel.maps.napt_from_lan.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(
            parse_lan_value(&val),
            LanValue {
                external_port: UDP_NAT_PORT,
                kind: KIND_DYNAMIC,
                generation: 0
            }
        );

        let key = from_wan_index(PROTO_UDP, UDP_NAT_PORT).to_ne_bytes();
        let val = skel.maps.napt_from_wan.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(
            parse_wan_value(&val),
            WanValue {
                internal_addr: LAN_HOST,
                internal_port: LAN_PORT,
                kind: KIND_DYNAMIC,
                generation: 0,
                state_ref: (STATE_ACTIVE << STATE_SHIFT) | 1,
            }
        );

        let key = ct_key(LAN_HOST, LAN_PORT, REMOTE_IP, REMOTE_PORT, PROTO_UDP);
        let val = skel.maps.napt_ct.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(
            parse_ct_value(&val),
            CtValue {
                external_port: UDP_NAT_PORT,
                is_static: 0,
                generation: 0,
                status: CT_ACTIVE
            }
        );

        let (ret, out) =
            run(&skel.progs.tc_v4_from_wan, &udp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, UDP_NAT_PORT));
        assert_eq!(ret, TC_ACT_OK);
        let out = parse_udp(&out);
        assert_eq!(out.src, REMOTE_IP);
        assert_eq!(out.dst, LAN_HOST);
        assert_eq!(out.sport, REMOTE_PORT);
        assert_eq!(out.dport, LAN_PORT);
    });
}

#[test]
fn lan_tcp_syn_and_ack() {
    with_skel(&[], &[TCP_NAT_PORT], &[], |skel| {
        let (ret, out) = run(
            &skel.progs.tc_v4_from_lan,
            &tcp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, TCP_REMOTE_PORT, true),
        );
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_tcp_ports(&out), (TCP_NAT_PORT, TCP_REMOTE_PORT));

        let (ret, out) = run(
            &skel.progs.tc_v4_from_lan,
            &tcp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, TCP_REMOTE_PORT, false),
        );
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_tcp_ports(&out), (TCP_NAT_PORT, TCP_REMOTE_PORT));

        let key = ct_key(LAN_HOST, LAN_PORT, REMOTE_IP, TCP_REMOTE_PORT, PROTO_TCP);
        let val = skel.maps.napt_ct.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(parse_ct_value(&val).status, CT_ACTIVE);

        let (ret, _) = run(
            &skel.progs.tc_v4_from_lan,
            &tcp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT + 1, TCP_REMOTE_PORT, false),
        );
        assert_eq!(ret, TC_ACT_SHOT);
    });
}

#[test]
fn lan_icmp_query_and_wan_reply() {
    with_skel(&[], &[], &[ICMP_EXTERNAL_ID], |skel| {
        let (ret, out) =
            run(&skel.progs.tc_v4_from_lan, &icmp_pkt(LAN_HOST, REMOTE_IP, ICMP_INTERNAL_ID, true));
        assert_eq!(ret, TC_ACT_UNSPEC);
        let (dst, id) = parse_icmp_dst_id(&out);
        assert_eq!(dst, REMOTE_IP);
        assert_eq!(id, ICMP_EXTERNAL_ID);

        let (ret, out) =
            run(&skel.progs.tc_v4_from_wan, &icmp_pkt(REMOTE_IP, WAN_IP, ICMP_EXTERNAL_ID, false));
        assert_eq!(ret, TC_ACT_OK);
        let (dst, id) = parse_icmp_dst_id(&out);
        assert_eq!(dst, LAN_HOST);
        assert_eq!(id, ICMP_INTERNAL_ID);
    });
}

#[test]
fn lan_static_udp_and_wan_reverse() {
    with_skel(&[], &[], &[], |skel| {
        seed_static(skel, PROTO_UDP, LAN_HOST, LAN_PORT, UDP_NAT_PORT);

        let (ret, out) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);
        let out = parse_udp(&out);
        assert_eq!(out.src, WAN_IP);
        assert_eq!(out.sport, UDP_NAT_PORT);

        let key = ct_key(LAN_HOST, LAN_PORT, REMOTE_IP, REMOTE_PORT, PROTO_UDP);
        let val = skel.maps.napt_ct.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(parse_ct_value(&val).is_static, 1);

        let (ret, out) =
            run(&skel.progs.tc_v4_from_wan, &udp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, UDP_NAT_PORT));
        assert_eq!(ret, TC_ACT_OK);
        let out = parse_udp(&out);
        assert_eq!(out.dst, LAN_HOST);
        assert_eq!(out.dport, LAN_PORT);
    });
}

#[test]
fn lan_udp_fragment_first_and_nonfirst() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let (ret, out) = run(&skel.progs.tc_v4_from_lan, &ipv4_frag_udp(true, 0x7777));
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_ipv4_src(&out), WAN_IP);
        let sport = u16::from_be_bytes([out[34], out[35]]);
        assert_eq!(sport, UDP_NAT_PORT);

        let (ret, out) = run(&skel.progs.tc_v4_from_lan, &ipv4_frag_udp(false, 0x7777));
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_ipv4_src(&out), WAN_IP);
    });
}

#[test]
fn wan_udp_without_mapping_drops() {
    with_skel(&[], &[], &[], |skel| {
        let (ret, _) =
            run(&skel.progs.tc_v4_from_wan, &udp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, UDP_NAT_PORT));
        assert_eq!(ret, TC_ACT_SHOT);
    });
}

#[test]
fn wan_icmp_error_rewrites_inner_udp_tuple() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let (ret, _) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);

        let pkt = icmp_error_wan(WAN_IP, REMOTE_IP, UDP_NAT_PORT, REMOTE_PORT, REMOTE_IP, WAN_IP);
        let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
        assert_eq!(ret, TC_ACT_OK);

        assert_eq!(parse_ipv4_dst(&out), LAN_HOST);

        let inner_src = Ipv4Addr::new(out[54], out[55], out[56], out[57]);
        assert_eq!(inner_src, LAN_HOST);
        let inner_sport = u16::from_be_bytes([out[62], out[63]]);
        assert_eq!(inner_sport, LAN_PORT);
    });
}

#[test]
fn closed_mapping_is_not_reused_and_requeued_generation_advances() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let (ret, _) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);

        let wan_key = from_wan_index(PROTO_UDP, UDP_NAT_PORT).to_ne_bytes();
        let ct_key = ct_key(LAN_HOST, LAN_PORT, REMOTE_IP, REMOTE_PORT, PROTO_UDP);
        skel.maps.napt_ct.delete(&ct_key).unwrap();

        let mut closed = [0u8; 32];
        closed[0..4].copy_from_slice(&LAN_HOST.octets());
        closed[4..6].copy_from_slice(&LAN_PORT.to_be_bytes());
        closed[6] = KIND_DYNAMIC;
        closed[16..20].copy_from_slice(&0u32.to_ne_bytes());
        closed[24..32].copy_from_slice(&((2u64 << STATE_SHIFT) | 1).to_ne_bytes());
        skel.maps.napt_from_wan.update(&wan_key, &closed, MapFlags::ANY).unwrap();

        let (ret, _) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_SHOT, "CLOSED mapping must not be reused");

        let lan_key = from_lan_key(LAN_HOST, LAN_PORT, PROTO_UDP);
        skel.maps.napt_from_lan.delete(&lan_key).unwrap();
        let free = [0u8; 32];
        skel.maps.napt_from_wan.update(&wan_key, &free, MapFlags::ANY).unwrap();
        queue_push(&skel.maps.napt_udp_ports, UDP_NAT_PORT, 1);

        let (ret, out) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);
        assert_eq!(parse_udp(&out).sport, UDP_NAT_PORT);

        let val = skel.maps.napt_from_lan.lookup(&lan_key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(parse_lan_value(&val).generation, 1);
        let val = skel.maps.napt_from_wan.lookup(&wan_key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(parse_wan_value(&val).generation, 1);
    });
}

#[test]
fn unallocated_wan_slot_is_free() {
    with_skel(&[], &[], &[], |skel| {
        let key = from_wan_index(PROTO_UDP, UDP_NAT_PORT).to_ne_bytes();
        let val = skel.maps.napt_from_wan.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(parse_wan_value(&val).kind, KIND_FREE);
    });
}

#[test]
fn static_wildcard_wan_keeps_original_destination() {
    with_skel(&[], &[], &[], |skel| {
        seed_static(skel, PROTO_UDP, Ipv4Addr::UNSPECIFIED, LAN_PORT, UDP_NAT_PORT);

        let (ret, out) =
            run(&skel.progs.tc_v4_from_wan, &udp_pkt(REMOTE_IP, WAN_IP, REMOTE_PORT, UDP_NAT_PORT));
        assert_eq!(ret, TC_ACT_OK);
        let out = parse_udp(&out);
        assert_eq!(out.dst, WAN_IP, "wildcard static must keep the original destination");
        assert_eq!(out.dport, LAN_PORT);
    });
}

#[test]
fn lan_broadcast_is_not_natted() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let broadcast = Ipv4Addr::new(255, 255, 255, 255);
        let (ret, _) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, broadcast, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);

        let key = from_wan_index(PROTO_UDP, UDP_NAT_PORT).to_ne_bytes();
        let wan = skel.maps.napt_from_wan.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(wan[6], KIND_FREE);
    });
}

#[test]
fn dynamic_mapping_without_allow_reuse_rejects_other_remote() {
    with_skel(&[], &[], &[], |skel| {
        let other_remote = Ipv4Addr::new(10, 0, 0, 2);
        seed_dynamic(skel, PROTO_UDP, LAN_HOST, LAN_PORT, UDP_NAT_PORT, REMOTE_IP, REMOTE_PORT, 0);

        let (ret, _) = run(
            &skel.progs.tc_v4_from_lan,
            &udp_pkt(LAN_HOST, other_remote, LAN_PORT, REMOTE_PORT),
        );
        assert_eq!(ret, TC_ACT_SHOT);

        let (ret, _) =
            run(&skel.progs.tc_v4_from_lan, &udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT));
        assert_eq!(ret, TC_ACT_UNSPEC);
    });
}

#[test]
fn dynamic_mapping_with_allow_reuse_accepts_other_remote() {
    with_skel(&[], &[], &[], |skel| {
        let other_remote = Ipv4Addr::new(10, 0, 0, 2);
        seed_dynamic(skel, PROTO_UDP, LAN_HOST, LAN_PORT, UDP_NAT_PORT, REMOTE_IP, REMOTE_PORT, 1);

        let (ret, _) = run(
            &skel.progs.tc_v4_from_lan,
            &udp_pkt(LAN_HOST, other_remote, LAN_PORT, REMOTE_PORT),
        );
        assert_eq!(ret, TC_ACT_UNSPEC);
    });
}

#[test]
fn dynamic_mapping_without_allow_reuse_rejects_other_wan_source() {
    with_skel(&[], &[], &[], |skel| {
        let other_remote = Ipv4Addr::new(10, 0, 0, 2);
        seed_dynamic(skel, PROTO_UDP, LAN_HOST, LAN_PORT, UDP_NAT_PORT, REMOTE_IP, REMOTE_PORT, 0);

        let (ret, _) = run(
            &skel.progs.tc_v4_from_wan,
            &udp_pkt(other_remote, WAN_IP, REMOTE_PORT, UDP_NAT_PORT),
        );
        assert_eq!(ret, TC_ACT_SHOT);
    });
}

#[test]
fn lan_broadcast_mac_is_not_natted() {
    with_skel(&[UDP_NAT_PORT], &[], &[], |skel| {
        let mut pkt = udp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT, REMOTE_PORT);
        pkt[0..6].fill(0xff);
        let (ret, _) = run(&skel.progs.tc_v4_from_lan, &pkt);
        assert_eq!(ret, TC_ACT_UNSPEC);

        let key = from_wan_index(PROTO_UDP, UDP_NAT_PORT).to_ne_bytes();
        let wan = skel.maps.napt_from_wan.lookup(&key, MapFlags::ANY).unwrap().unwrap();
        assert_eq!(wan[6], KIND_FREE);
    });
}
