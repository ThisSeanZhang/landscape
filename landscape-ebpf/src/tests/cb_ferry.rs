//! cb ferry equivalence: running the production chain roots (which scan
//! once and pack skb->cb) wired to a real stage must produce exactly the
//! same verdict and output bytes as running the stage directly with a
//! zeroed cb (the in-stage fallback scan).  Also asserts the packed cb
//! layout for known packets.

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd};

use etherparse::{
    Ethernet2Header, IcmpEchoHeader, Icmpv4Type, IpFragOffset, Ipv6FragmentHeader, Ipv6Header,
    PacketBuilder, TcpHeader, TcpOptionElement, TransportHeader, ether_type, icmpv4, ip_number,
};
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::landscape::OwnedOpenObject;
use crate::skel::tc_firewall::TcFirewallSkelBuilder;
use crate::skel::tc_mss::TcMssSkelBuilder;
use crate::skel::tc_nat4::TcNat4SkelBuilder;
use crate::tests::TestSkb;

const TC_SLOT_V4: u32 = 0;
const TC_SLOT_V6: u32 = 1;
const CHAIN: u32 = 0x1234;
const L3: u32 = 14;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const IFINDEX: u32 = 6;

const V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

// ── roots ──

struct IngressRoot {
    skel: crate::skel::tc_wan_ingress_root::TcWanIngressRootSkel<'static>,
    _backing: OwnedOpenObject,
}

fn load_ingress_root() -> IngressRoot {
    let (backing, object) = OwnedOpenObject::new();
    let mut open = crate::skel::tc_wan_ingress_root::TcWanIngressRootSkelBuilder::default()
        .open(object)
        .unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = L3;
    open.maps.rodata_data.as_deref_mut().unwrap().current_chain = CHAIN;
    IngressRoot { skel: open.load().unwrap(), _backing: backing }
}

struct EgressRoot {
    skel: crate::skel::tc_wan_egress_root::TcWanEgressRootSkel<'static>,
    _backing: OwnedOpenObject,
}

fn load_egress_root() -> EgressRoot {
    let (backing, object) = OwnedOpenObject::new();
    let mut open = crate::skel::tc_wan_egress_root::TcWanEgressRootSkelBuilder::default()
        .open(object)
        .unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = L3;
    EgressRoot { skel: open.load().unwrap(), _backing: backing }
}

fn wire_stage(map: &impl MapCore, slot: u32, prog: &ProgramMut<'_>) {
    let fd = prog.as_fd().as_raw_fd();
    map.update(&slot.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY).unwrap();
}

// ── runners ──

fn run_prog(prog: &ProgramMut<'_>, pkt: &[u8]) -> (i32, Vec<u8>, [u32; 5]) {
    let mut ctx = TestSkb::default();
    let mut ctx_out = TestSkb::default();
    let mut out = vec![0_u8; pkt.len()];
    let ret = prog
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("test_run failed")
        .return_value as i32;
    (ret, out, ctx_out.cb)
}

/// root (cb packed) vs direct stage (zeroed cb → fallback): same verdict,
/// same bytes.
fn assert_equiv(root_prog: &ProgramMut<'_>, stage_prog: &ProgramMut<'_>, pkt: &[u8], label: &str) {
    let (ret_root, out_root, _) = run_prog(root_prog, pkt);
    let (ret_direct, out_direct, _) = run_prog(stage_prog, pkt);
    assert_eq!(ret_root, ret_direct, "{label}: verdict differs");
    assert_eq!(out_root, out_direct, "{label}: output bytes differ");
}

// ── packet builders ──

fn ipv4_tcp_syn_mss(mss: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(LAN_HOST.octets(), REMOTE_IP.octets(), 64)
        .tcp(12345, 443, 0x1020_3040, 4096)
        .syn()
        .options(&[TcpOptionElement::MaximumSegmentSize(mss)])
        .unwrap();
    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn ipv4_udp() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(LAN_HOST.octets(), REMOTE_IP.octets(), 64)
        .udp(5353, 53);
    let payload = [0_u8; 8];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn ipv4_icmp_echo(id: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(LAN_HOST.octets(), REMOTE_IP.octets(), 64)
        .icmpv4(Icmpv4Type::EchoRequest(IcmpEchoHeader { id, seq: 1 }));
    let payload = [0xab_u8; 8];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

/// icmp error quoting a minimal inner TCP header; the inner saddr must
/// equal the outer daddr or the scanner rejects the packet.
fn ipv4_icmp_error_quoting_tcp(
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    sp: u16,
    dp: u16,
) -> Vec<u8> {
    let inner = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv4(inner_src.octets(), inner_dst.octets(), 64)
        .tcp(sp, dp, 0x1234_5678, 65535);
    let mut quoted = Vec::with_capacity(inner.size(0));
    inner.write(&mut quoted, &[]).unwrap();
    let quoted = quoted[14..14 + 20 + 8].to_vec();

    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1])
        .ipv4(REMOTE_IP.octets(), WAN_IP.octets(), 64)
        .icmpv4(Icmpv4Type::TimeExceeded(icmpv4::TimeExceededCode::TtlExceededInTransit));
    let mut buf = Vec::with_capacity(builder.size(quoted.len()));
    builder.write(&mut buf, &quoted).unwrap();
    buf
}

/// Patch an ipv4 packet's fragment id / flags+offset (post-build).
fn ipv4_set_frag(pkt: &mut [u8], id: u16, flags_off: u16) {
    let l3 = L3 as usize;
    pkt[l3 + 4..l3 + 6].copy_from_slice(&id.to_be_bytes());
    pkt[l3 + 6..l3 + 8].copy_from_slice(&flags_off.to_be_bytes());
}

fn v6_tcp_syn_mss(mss: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
        .ipv6(V6_SRC.octets(), V6_DST.octets(), 64)
        .tcp(12345, 443, 0x1020_3040, 4096)
        .syn()
        .options(&[TcpOptionElement::MaximumSegmentSize(mss)])
        .unwrap();
    let payload = [0x11_u8, 0x22, 0x33, 0x44];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

fn v6_frag_tcp(mss: u16, frag_offset: u16, more: bool) -> Vec<u8> {
    let payload = [0x11_u8, 0x22, 0x33, 0x44];

    let mut tcp = TcpHeader::new(12345, 443, 0x1020_3040, 4096);
    tcp.syn = true;
    tcp.set_options(&[TcpOptionElement::MaximumSegmentSize(mss)]).unwrap();
    tcp.checksum = tcp.calc_checksum_ipv6_raw(V6_SRC.octets(), V6_DST.octets(), &payload).unwrap();

    let mut tcp_and_payload = Vec::with_capacity(tcp.header_len() + payload.len());
    tcp.write(&mut tcp_and_payload).unwrap();
    tcp_and_payload.extend_from_slice(&payload);

    let mut ipv6 = Ipv6Header {
        traffic_class: 0,
        flow_label: Default::default(),
        payload_length: 0,
        next_header: ip_number::IPV6_FRAGMENTATION_HEADER,
        hop_limit: 64,
        source: V6_SRC.octets(),
        destination: V6_DST.octets(),
    };
    ipv6.set_payload_length(Ipv6FragmentHeader::LEN + tcp_and_payload.len()).unwrap();
    let fragment = Ipv6FragmentHeader::new(
        ip_number::TCP,
        IpFragOffset::try_new(frag_offset).unwrap(),
        more,
        7,
    );
    let eth = Ethernet2Header {
        source: [2, 0, 0, 0, 0, 1],
        destination: [2, 0, 0, 0, 0, 2],
        ether_type: ether_type::IPV6,
    };

    let mut packet = Vec::new();
    eth.write(&mut packet).unwrap();
    ipv6.write(&mut packet).unwrap();
    fragment.write(&mut packet).unwrap();
    packet.extend_from_slice(&tcp_and_payload);
    packet
}

fn tcp_mss_of(pkt: &[u8]) -> Option<u16> {
    let headers = etherparse::PacketHeaders::from_ethernet_slice(pkt).expect("parse packet");
    let Some(TransportHeader::Tcp(tcp)) = headers.transport else { return None };
    let mut options = tcp.options.as_slice();
    while !options.is_empty() {
        match options[0] {
            0 => return None,
            1 => options = &options[1..],
            2 if options.len() >= 4 && options[1] == 4 => {
                return Some(u16::from_be_bytes([options[2], options[3]]));
            }
            _ if options.len() >= 2 && options[1] >= 2 && options[1] as usize <= options.len() => {
                options = &options[options[1] as usize..];
            }
            _ => return None,
        }
    }
    None
}

// ── cb layout constants (mirror of chain/tc_cb.h) ──

mod cb {
    pub const MAGIC: u32 = 0x53A2;

    pub fn scan_valid(cb0: u32) -> bool {
        (cb0 >> 1) & 0x7FFF == MAGIC && (cb0 >> 16) & 1 == 1
    }
    pub fn ports_valid(cb0: u32) -> bool {
        (cb0 >> 17) & 1 == 1
    }
    pub fn frag(cb0: u32) -> u32 {
        (cb0 >> 18) & 7
    }
    pub fn l4_offset(cb2: u32) -> u32 {
        cb2 & 0x7FFF
    }
    pub fn l4_protocol(cb2: u32) -> u32 {
        (cb2 >> 16) & 0xFF
    }
    pub fn pkt_type(cb2: u32) -> u32 {
        cb2 >> 24
    }
    pub fn sport(cb3: u32) -> u16 {
        u16::from_be((cb3 & 0xFFFF) as u16)
    }
    pub fn dport(cb3: u32) -> u16 {
        u16::from_be((cb3 >> 16) as u16)
    }
    pub fn icmp_inner_l4(cb4: u32) -> u32 {
        cb4 & 0x7FFF
    }
    pub fn icmp_l4_protocol(cb4: u32) -> u32 {
        (cb4 >> 16) & 0xFF
    }
}

// PKT_TCP_SYN_V2 from einat_types.h
const PKT_TCP_SYN_V2: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    fn mss_skel() -> crate::skel::tc_mss::TcMssSkel<'static> {
        let (backing, object) = OwnedOpenObject::new();
        let mut open = TcMssSkelBuilder::default().open(object).unwrap();
        open.maps.rodata_data.as_deref_mut().unwrap().mtu_size = 1492;
        open.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = L3;
        let skel = open.load().unwrap();
        std::mem::forget(backing);
        skel
    }

    #[test]
    fn ferry_cb_layout_tcp_udp_icmp() {
        let root = load_ingress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &mss.progs.tc_mss_wan_ingress_v4,
        );

        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &ipv4_tcp_syn_mss(1460));
        assert!(cb::scan_valid(c[0]));
        assert!(cb::ports_valid(c[0]));
        assert_eq!(cb::frag(c[0]), 0);
        assert_eq!(c[1], (CHAIN << 16) | L3, "ingress stamp: chain | l3");
        assert_eq!(cb::l4_offset(c[2]), L3 + 20, "l4 offset points at the TCP header");
        assert_eq!(cb::l4_protocol(c[2]), 6);
        assert_eq!(cb::pkt_type(c[2]), PKT_TCP_SYN_V2);
        assert_eq!(cb::sport(c[3]), 12345);
        assert_eq!(cb::dport(c[3]), 443);
        assert_eq!(cb::icmp_inner_l4(c[4]), 0);
        assert_eq!(cb::icmp_l4_protocol(c[4]), 0);

        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &ipv4_udp());
        assert_eq!(cb::l4_protocol(c[2]), 17);
        assert_eq!(cb::pkt_type(c[2]), 0);

        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &ipv4_icmp_echo(0x4321));
        assert_eq!(cb::l4_protocol(c[2]), 1);
        assert_eq!(cb::sport(c[3]), 0x4321, "icmp echo id rides both port halves");
        assert_eq!(cb::dport(c[3]), 0x4321);
    }

    #[test]
    fn ferry_cb_layout_icmpx_and_frag() {
        let root = load_ingress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &mss.progs.tc_mss_wan_ingress_v4,
        );

        // icmp error quoting inner TCP: cb[4] carries the inner walk and the
        // ports are the (swapped) inner pair.
        let pkt = ipv4_icmp_error_quoting_tcp(WAN_IP, REMOTE_IP, 5555, 6666);
        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &pkt);
        assert!(cb::scan_valid(c[0]));
        assert!(cb::ports_valid(c[0]));
        assert!(cb::icmp_inner_l4(c[4]) > 0);
        assert_eq!(cb::icmp_l4_protocol(c[4]), 6);
        assert_eq!(cb::sport(c[3]), 6666, "icmpx ports swapped: src = inner dport");
        assert_eq!(cb::dport(c[3]), 5555);
        // FIRST fragment: cache write + packet ports.
        let mut first = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut first, 0x77, 0x2000);
        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &first);
        assert_eq!(cb::frag(c[0]), 1);
        assert!(cb::ports_valid(c[0]));

        // MIDDLE fragment, same id: cache hit restores the FIRST ports.
        let mut middle = vec![0x55_u8; 74];
        middle[12] = 0x08;
        middle[13] = 0x00;
        middle[14] = 0x45;
        middle[14 + 9] = 6; // TCP: the frag cache key includes l4proto
        middle[14 + 4..14 + 6].copy_from_slice(&0x77u16.to_be_bytes());
        middle[14 + 6..14 + 8].copy_from_slice(&0x2001u16.to_be_bytes());
        middle[14 + 12..14 + 16].copy_from_slice(&LAN_HOST.octets());
        middle[14 + 16..14 + 20].copy_from_slice(&REMOTE_IP.octets());
        let (_, _, c) = run_prog(&root.skel.progs.tc_wan_ingress_root, &middle);
        assert_eq!(cb::frag(c[0]), 2);
        assert!(cb::ports_valid(c[0]), "MIDDLE after FIRST: frag cache hit");
        assert_eq!(cb::sport(c[3]), 12345);
        assert_eq!(cb::l4_offset(c[2]), 0, "no L4 header on MIDDLE fragments");

        // MIDDLE without a prior FIRST (fresh root object): cache miss.
        let root2 = load_ingress_root();
        let (_, _, c) = run_prog(&root2.skel.progs.tc_wan_ingress_root, &middle);
        assert!(!cb::ports_valid(c[0]), "cache miss → PORTS_INVALID");
    }

    #[test]
    fn ferry_equivalence_mss_v4() {
        let root = load_egress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_egress_root_next_stage,
            TC_SLOT_V4,
            &mss.progs.tc_mss_wan_egress_v4,
        );
        let root_prog = &root.skel.progs.tc_wan_egress_root;

        let syn = ipv4_tcp_syn_mss(1460);
        assert_equiv(root_prog, &mss.progs.tc_mss_wan_egress_v4, &syn, "v4 syn");
        let (_, out, _) = run_prog(root_prog, &syn);
        assert_eq!(tcp_mss_of(&out), Some(1492 - 20 - 20), "root path still clamps");

        assert_equiv(root_prog, &mss.progs.tc_mss_wan_egress_v4, &ipv4_udp(), "v4 udp");
        assert_equiv(root_prog, &mss.progs.tc_mss_wan_egress_v4, &ipv4_icmp_echo(1), "v4 icmp");

        let mut first = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut first, 0x77, 0x2000);
        assert_equiv(root_prog, &mss.progs.tc_mss_wan_egress_v4, &first, "v4 frag FIRST");

        // Decision ①: a MIDDLE fragment's payload must never be parsed as a
        // TCP header, even when it mimics SYN+MSS.
        let mut middle = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut middle, 0x78, 0x2001);
        let (_, out, _) = run_prog(root_prog, &middle);
        assert_eq!(out, middle, "cb path leaves non-first fragments alone");
    }

    #[test]
    fn ferry_equivalence_mss_v6() {
        let root = load_egress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_egress_root_next_stage,
            TC_SLOT_V6,
            &mss.progs.tc_mss_wan_egress_v6,
        );
        let root_prog = &root.skel.progs.tc_wan_egress_root;

        let syn = v6_tcp_syn_mss(1460);
        assert_equiv(root_prog, &mss.progs.tc_mss_wan_egress_v6, &syn, "v6 syn");
        let (_, out, _) = run_prog(root_prog, &syn);
        assert_eq!(tcp_mss_of(&out), Some(1492 - 40 - 20));

        // Decision ②: any v6 frag header (even atomic offset-0 !MF) skips.
        let atomic = v6_frag_tcp(1460, 0, false);
        let (_, out, _) = run_prog(root_prog, &atomic);
        assert_eq!(out, atomic, "atomic v6 fragment is not clamped");
        let first = v6_frag_tcp(1460, 0, true);
        let (_, out, _) = run_prog(root_prog, &first);
        assert_eq!(out, first, "v6 FRAG_FIRST is not clamped");
    }

    #[test]
    fn ferry_equivalence_firewall_v4() {
        let root = load_ingress_root();
        let (_fw_backing, fw_obj) = OwnedOpenObject::new();
        let fw = TcFirewallSkelBuilder::default().open(fw_obj).unwrap().load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &fw.progs.tc_firewall_wan_ingress_v4,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v4,
            &ipv4_tcp_syn_mss(1460),
            "fw v4 tcp",
        );
        assert_equiv(root_prog, &fw.progs.tc_firewall_wan_ingress_v4, &ipv4_udp(), "fw v4 udp");
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v4,
            &ipv4_icmp_echo(9),
            "fw v4 icmp echo",
        );
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v4,
            &ipv4_icmp_error_quoting_tcp(WAN_IP, REMOTE_IP, 5555, 6666),
            "fw v4 icmpx",
        );

        let mut first = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut first, 0x91, 0x2000);
        assert_equiv(root_prog, &fw.progs.tc_firewall_wan_ingress_v4, &first, "fw v4 frag FIRST");

        let mut middle = first.clone();
        ipv4_set_frag(&mut middle, 0x91, 0x2001);
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v4,
            &middle,
            "fw v4 frag MIDDLE after FIRST",
        );

        // MIDDLE with no prior FIRST on either path: root cache miss and fw
        // cache miss both SHOT.
        let mut orphan = first.clone();
        ipv4_set_frag(&mut orphan, 0x92, 0x2001);
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v4,
            &orphan,
            "fw v4 orphan MIDDLE",
        );
        let (ret, _, _) = run_prog(root_prog, &orphan);
        assert_eq!(ret, 2, "orphan fragment is dropped");
    }

    #[test]
    fn ferry_equivalence_firewall_v6() {
        let root = load_ingress_root();
        let (_fw_backing, fw_obj) = OwnedOpenObject::new();
        let fw = TcFirewallSkelBuilder::default().open(fw_obj).unwrap().load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V6,
            &fw.progs.tc_firewall_wan_ingress_v6,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v6,
            &v6_tcp_syn_mss(1460),
            "fw v6 tcp",
        );
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v6,
            &v6_frag_tcp(1460, 0, false),
            "fw v6 atomic frag",
        );
        assert_equiv(
            root_prog,
            &fw.progs.tc_firewall_wan_ingress_v6,
            &v6_frag_tcp(1460, 0, true),
            "fw v6 frag FIRST",
        );
    }

    #[test]
    fn ferry_equivalence_nat4_static() {
        use crate::NAT_MAPPING_INGRESS;
        use crate::maps::nat::{StaticNatMappingV4Item, add_static_nat4_mapping_v3};
        use crate::maps::{Nat4TimerKey, Nat4TimerValueV3};

        let root = load_ingress_root();
        let pin_root = crate::tests::isolated_pin_root("cb-ferry-nat4");
        let mut builder = TcNat4SkelBuilder::default();
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = builder.open(&mut open_object).unwrap();
        open_skel.maps.rodata_data.as_deref_mut().unwrap().wan_ro_addr4 =
            crate::stages::nat4::wan_ro_addr4(WAN_IP);
        let nat = open_skel.load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &nat.progs.tc_nat_wan_ingress_v4,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        add_static_nat4_mapping_v3(
            &nat.maps.nat4_static_map,
            vec![StaticNatMappingV4Item {
                wan_port: 8080,
                lan_port: 80,
                lan_ip: LAN_HOST,
                l4_protocol: 6,
            }],
        );
        let key = Nat4TimerKey {
            l4proto: 6,
            _pad: [0; 3],
            src_addr: REMOTE_IP.to_bits().to_be(),
            dst_addr: WAN_IP.to_bits().to_be(),
            src_port: 9999u16.to_be(),
            dst_port: 8080u16.to_be(),
        };
        let value = Nat4TimerValueV3 {
            server_status: 1,
            client_status: 1,
            gress: NAT_MAPPING_INGRESS,
            client_addr: LAN_HOST.to_bits().to_be(),
            client_port: 80u16.to_be(),
            ifindex: IFINDEX,
            ..Default::default()
        };
        nat.maps.nat4_timer_map.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY).unwrap();

        // Plain TCP: both paths DNAT identically (byte-level, checksums
        // included) — and the translation really happened.
        let pkt = ipv4_tcp_to(WAN_IP, 9999, 8080);
        assert_equiv(root_prog, &nat.progs.tc_nat_wan_ingress_v4, &pkt, "nat v4 tcp");
        let (ret, out, _) = run_prog(root_prog, &pkt);
        assert_eq!(ret, 0);
        let headers = etherparse::PacketHeaders::from_ethernet_slice(&out).unwrap();
        match headers.net {
            Some(etherparse::NetHeaders::Ipv4(ip, _)) => {
                assert_eq!(Ipv4Addr::from(ip.destination), LAN_HOST);
            }
            _ => panic!("expected ipv4"),
        }

        // icmp error quoting the translated flow: exercises the cb[4] icmpx
        // fields through NAT's modify path.
        let icmpx = ipv4_icmp_error_quoting_tcp(WAN_IP, REMOTE_IP, 8080, 9999);
        assert_equiv(root_prog, &nat.progs.tc_nat_wan_ingress_v4, &icmpx, "nat v4 icmpx");

        // fragmented TCP: FIRST then MIDDLE ride the root/nat frag caches.
        let mut first = ipv4_tcp_to(WAN_IP, 9999, 8080);
        ipv4_set_frag(&mut first, 0x33, 0x2000);
        assert_equiv(root_prog, &nat.progs.tc_nat_wan_ingress_v4, &first, "nat v4 frag FIRST");
        let mut middle = first.clone();
        ipv4_set_frag(&mut middle, 0x33, 0x2001);
        assert_equiv(root_prog, &nat.progs.tc_nat_wan_ingress_v4, &middle, "nat v4 frag MIDDLE");
    }

    fn ipv4_tcp_to(dst: Ipv4Addr, sp: u16, dp: u16) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1])
            .ipv4(REMOTE_IP.octets(), dst.octets(), 64)
            .tcp(sp, dp, 0x1234_5678, 65535);
        let mut buf = Vec::with_capacity(builder.size(0));
        builder.write(&mut buf, &[]).unwrap();
        buf
    }
}
