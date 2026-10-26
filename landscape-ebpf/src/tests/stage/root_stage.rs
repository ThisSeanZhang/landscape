//! Root + stage integration: production chain roots tail-call into real
//! stages. Roots only stamp chain/l3 into skb->cb; each stage re-reads the
//! packet. These tests assert the stage behaviour on the root path and the
//! fragment/cache decisions that used to be cached in cb.

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
use crate::tests::TestSkb;

const TC_SLOT_V4: u32 = 0;
const TC_SLOT_V6: u32 = 1;
const CHAIN: u32 = 0x1234;
const L3: u32 = 14;

const WAN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

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

fn ipv4_icmp_echo_reply(id: u16) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 1])
        .ipv4(REMOTE_IP.octets(), WAN_IP.octets(), 64)
        .icmpv4(Icmpv4Type::EchoReply(IcmpEchoHeader { id, seq: 1 }));
    let payload = [0xab_u8; 8];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut buf, &payload).unwrap();
    buf
}

/// icmp error quoting a minimal inner TCP header; the inner saddr must
/// equal the outer daddr or the NAT reader rejects the packet.
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

    fn run_root(prog: &ProgramMut<'_>, pkt: &[u8]) -> (i32, Vec<u8>) {
        let (ret, out, _) = run_prog(prog, pkt);
        (ret, out)
    }

    fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
        let headers = etherparse::PacketHeaders::from_ethernet_slice(pkt).ok()?;
        match headers.net {
            Some(etherparse::NetHeaders::Ipv4(ip, _)) => Some(Ipv4Addr::from(ip.destination)),
            _ => None,
        }
    }

    #[test]
    fn root_stamps_chain_and_l3_without_caching_parse() {
        let root = load_ingress_root();
        let pkt = ipv4_tcp_syn_mss(1460);
        let (ret, out, cb) = run_prog(&root.skel.progs.tc_wan_ingress_root, &pkt);

        assert_eq!(ret, 0);
        assert_eq!(out, pkt, "no stage wired: packet leaves unchanged");
        assert_eq!(cb[0] & 1, 0, "not forwarded");
        assert_eq!(cb[1], (CHAIN << 16) | L3, "chain id | l3 offset");
        assert_eq!(&cb[2..], &[0, 0, 0], "no parse cache in cb[2..4]");
    }

    #[test]
    fn root_stage_mss_v4() {
        let root = load_egress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_egress_root_next_stage,
            TC_SLOT_V4,
            &mss.progs.tc_mss_wan_egress_v4,
        );
        let root_prog = &root.skel.progs.tc_wan_egress_root;

        let syn = ipv4_tcp_syn_mss(1460);
        let (_, out) = run_root(root_prog, &syn);
        assert_eq!(tcp_mss_of(&out), Some(1492 - 20 - 20), "root path still clamps");

        for pkt in [ipv4_udp(), ipv4_icmp_echo(1)] {
            let (_, out) = run_root(root_prog, &pkt);
            assert_eq!(out, pkt, "non-TCP leaves the packet alone");
        }

        let mut first = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut first, 0x77, 0x2000);
        let (_, out) = run_root(root_prog, &first);
        let mss_opt = L3 as usize + 20 + 20;
        assert_eq!(
            u16::from_be_bytes([out[mss_opt + 2], out[mss_opt + 3]]),
            1492 - 20 - 20,
            "FIRST fragment carries the TCP header and is clamped"
        );

        // A MIDDLE fragment's payload must never be parsed as a TCP header,
        // even when it mimics SYN+MSS.
        let mut middle = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut middle, 0x78, 0x2001);
        let (_, out) = run_root(root_prog, &middle);
        assert_eq!(out, middle, "non-first fragments are left alone");
    }

    #[test]
    fn root_stage_mss_v6() {
        let root = load_egress_root();
        let mss = mss_skel();
        wire_stage(
            &root.skel.maps.wan_egress_root_next_stage,
            TC_SLOT_V6,
            &mss.progs.tc_mss_wan_egress_v6,
        );
        let root_prog = &root.skel.progs.tc_wan_egress_root;

        let syn = v6_tcp_syn_mss(1460);
        let (_, out) = run_root(root_prog, &syn);
        assert_eq!(tcp_mss_of(&out), Some(1492 - 40 - 20));

        let atomic = v6_frag_tcp(1460, 0, false);
        let (_, out) = run_root(root_prog, &atomic);
        assert_eq!(out, atomic, "atomic v6 fragment is not clamped");
        let first = v6_frag_tcp(1460, 0, true);
        let (_, out) = run_root(root_prog, &first);
        assert_eq!(out, first, "v6 FRAG_FIRST is not clamped");
    }

    #[test]
    fn root_stage_firewall_v4() {
        let root = load_ingress_root();
        let (_fw_backing, fw_obj) = OwnedOpenObject::new();
        let fw = TcFirewallSkelBuilder::default().open(fw_obj).unwrap().load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &fw.progs.tc_firewall_wan_ingress_v4,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        for pkt in [
            ipv4_tcp_syn_mss(1460),
            ipv4_udp(),
            ipv4_icmp_echo_reply(9),
            ipv4_icmp_error_quoting_tcp(WAN_IP, REMOTE_IP, 5555, 6666),
        ] {
            let (ret, out) = run_root(root_prog, &pkt);
            assert_eq!(ret, 0);
            assert_eq!(out, pkt, "no block entry: pass unchanged");
        }

        let mut first = ipv4_tcp_syn_mss(1460);
        ipv4_set_frag(&mut first, 0x91, 0x2000);
        let (ret, out) = run_root(root_prog, &first);
        assert_eq!(ret, 0);
        assert_eq!(out, first);

        let mut middle = first.clone();
        ipv4_set_frag(&mut middle, 0x91, 0x2001);
        let (ret, out) = run_root(root_prog, &middle);
        assert_eq!(ret, 0);
        assert_eq!(out, middle);

        // The firewall only enforces the IP block map now, so an orphan
        // fragment is allowed.
        let mut orphan = first.clone();
        ipv4_set_frag(&mut orphan, 0x92, 0x2001);
        let (ret, out) = run_root(root_prog, &orphan);
        assert_eq!(ret, 0, "orphan fragment is allowed");
        assert_eq!(out, orphan);
    }

    #[test]
    fn root_stage_firewall_v6() {
        let root = load_ingress_root();
        let (_fw_backing, fw_obj) = OwnedOpenObject::new();
        let fw = TcFirewallSkelBuilder::default().open(fw_obj).unwrap().load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V6,
            &fw.progs.tc_firewall_wan_ingress_v6,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        for pkt in [v6_tcp_syn_mss(1460), v6_frag_tcp(1460, 0, false), v6_frag_tcp(1460, 0, true)] {
            let (ret, out) = run_root(root_prog, &pkt);
            assert_eq!(ret, 0);
            assert_eq!(out, pkt);
        }
    }

    #[test]
    fn root_stage_nat4_static() {
        use crate::skel::tc_nat4_v4::{TcNat4V4Skel, TcNat4V4SkelBuilder, types};

        fn be32(addr: Ipv4Addr) -> u32 {
            u32::from_ne_bytes(addr.octets())
        }

        fn seed_static(nat: &TcNat4V4Skel<'_>) {
            use types::*;

            let lan_key = napt_from_lan_key {
                internal_addr: be32(LAN_HOST),
                internal_port: 80u16.to_be(),
                proto: 6,
                pad: 0,
            };
            let lan_value = napt_from_lan_value {
                external_port: 8080u16.to_be(),
                kind: 2,
                allow_reuse: 1,
                generation: 0,
                trigger_addr: 0,
                trigger_port: 0,
                pad: 0,
            };
            nat.maps
                .napt_from_lan
                .update(
                    crate::tests::helper::map::as_bytes(&lan_key),
                    crate::tests::helper::map::as_bytes(&lan_value),
                    MapFlags::ANY,
                )
                .unwrap();

            let wan_value = napt_from_wan_value {
                internal_addr: be32(LAN_HOST),
                internal_port: 80u16.to_be(),
                kind: 2,
                allow_reuse: 1,
                trigger_addr: 0,
                trigger_port: 0,
                pad0: 0,
                generation: 0,
                pad1: 0,
                state_ref: 1u64 << 56,
            };
            nat.maps
                .napt_from_wan
                .update(
                    &(65536u32 + 8080).to_ne_bytes(),
                    crate::tests::helper::map::as_bytes(&wan_value),
                    MapFlags::ANY,
                )
                .unwrap();

            let ct_key = napt_ct_key {
                internal_addr: be32(LAN_HOST),
                remote_addr: be32(REMOTE_IP),
                internal_port: 80u16.to_be(),
                remote_port: 9999u16.to_be(),
                proto: 6,
                pad: [0; 3],
            };
            let ct_value = napt_ct_value {
                external_port: 8080u16.to_be(),
                is_static: 1,
                from_wan_gen: 0,
                status: 20,
                ..Default::default()
            };
            nat.maps
                .napt_ct
                .update(
                    crate::tests::helper::map::as_bytes(&ct_key),
                    crate::tests::helper::map::as_bytes(&ct_value),
                    MapFlags::ANY,
                )
                .unwrap();
        }

        let root = load_ingress_root();
        let (_backing, object) = OwnedOpenObject::new();
        let mut open_skel = TcNat4V4SkelBuilder::default().open(object).unwrap();
        {
            let rodata = open_skel.maps.rodata_data.as_deref_mut().unwrap();
            rodata.current_l3_offset = L3;
            rodata.land_nat_external_addr = crate::stages::nat4::wan_ro_addr4(WAN_IP);
            rodata.land_nat_udp_range_start = 32768;
            rodata.land_nat_udp_range_end = 65535;
            rodata.land_nat_tcp_range_start = 32768;
            rodata.land_nat_tcp_range_end = 65535;
        }
        let nat = open_skel.load().unwrap();
        wire_stage(
            &root.skel.maps.wan_ingress_root_next_stage,
            TC_SLOT_V4,
            &nat.progs.tc_v4_from_wan,
        );
        let root_prog = &root.skel.progs.tc_wan_ingress_root;

        seed_static(&nat);

        // Plain TCP: the root no longer parses, NAT re-reads and DNATs.
        let pkt = ipv4_tcp_to(WAN_IP, 9999, 8080);
        let (ret, out) = run_root(root_prog, &pkt);
        assert_eq!(ret, 0);
        assert_eq!(ipv4_dst(&out), Some(LAN_HOST));

        // icmp error quoting the translated flow.
        let icmpx = ipv4_icmp_error_quoting_tcp(WAN_IP, REMOTE_IP, 8080, 9999);
        let (ret, out) = run_root(root_prog, &icmpx);
        assert_eq!(ret, 0);
        assert_eq!(ipv4_dst(&out), Some(LAN_HOST));

        // fragmented TCP: FIRST writes NAT's frag cache, MIDDLE reads it.
        let mut first = ipv4_tcp_to(WAN_IP, 9999, 8080);
        ipv4_set_frag(&mut first, 0x33, 0x2000);
        let (ret, out) = run_root(root_prog, &first);
        assert_eq!(ret, 0);
        assert_eq!(ipv4_dst(&out), Some(LAN_HOST));

        let mut middle = first.clone();
        ipv4_set_frag(&mut middle, 0x33, 0x2001);
        let (ret, out) = run_root(root_prog, &middle);
        assert_eq!(ret, 0);
        assert_eq!(ipv4_dst(&out), Some(LAN_HOST));
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
