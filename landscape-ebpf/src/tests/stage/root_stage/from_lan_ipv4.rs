use super::*;
use crate::skel::tc_wan_egress_exit::TcWanEgressExitSkelBuilder;
use crate::skel::tc_wan_egress_root::types::wan_egress_binding;
use crate::tests::helper::map::{host_direct_mark, insert_ip_mac_v4};
use crate::tests::pkt::{simple_ipv4_tcp, simple_ipv6_tcp_syn};
use landscape_common::net::MacAddr;

const IFINDEX: u32 = 1; // loopback in PROG_TEST_RUN
const WAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 8);
const SRC: MacAddr = MacAddr(2, 0, 0, 0, 0, 10);
const GW_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
const PEER_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 11);

const WAN6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const PEER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 11);
const REMOTE6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
const GW6_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 0x21);

fn binding() -> wan_egress_binding {
    wan_egress_binding {
        ifindex: IFINDEX,
        has_l2: 1,
        has_ipv4: 1,
        wan_ip4: u32::from_ne_bytes(WAN.octets()),
        wan_mask4: u32::from_ne_bytes([255, 255, 255, 0]),
        gateway_ip4: u32::from_ne_bytes(GATEWAY.octets()),
        source_mac: SRC.octets(),
        ..Default::default()
    }
}

fn forwarded() -> TestSkb {
    TestSkb {
        ifindex: IFINDEX,
        cb: [1, 9 << 16, 0, 0, 0],
        ..Default::default()
    }
}

#[test]
fn on_link_uses_host_and_off_link_uses_gateway_only_on_the_target_interface() {
    let root = load_egress_root_with(binding());
    let prog = &root.skel.progs.tc_wan_egress_root;
    let neighbours = &root.skel.maps.ip_mac_v4;
    insert_ip_mac_v4(neighbours, REMOTE, PEER_MAC, GW_MAC, IFINDEX);
    for (dst, next_hop, dmac) in [(PEER, PEER, PEER_MAC), (REMOTE, GATEWAY, GW_MAC)] {
        let packet = simple_ipv4_tcp(LAN_HOST, dst);
        // Populate both keys. A wrong-link entry for the selected next hop
        // must not make the root use the other key, even when that key hits.
        insert_ip_mac_v4(neighbours, GATEWAY, GW_MAC, PEER_MAC, IFINDEX);
        insert_ip_mac_v4(neighbours, next_hop, dmac, PEER_MAC, IFINDEX + 1);
        let (_, out, cb) = run_prog_with_ctx(prog, &packet, forwarded());
        assert_eq!(out, packet);
        assert_eq!(&cb[2..], &[0x4e483450, u32::from_ne_bytes(next_hop.octets()), IFINDEX]);

        insert_ip_mac_v4(neighbours, next_hop, dmac, PEER_MAC, IFINDEX);
        let (_, out, cb) = run_prog_with_ctx(prog, &packet, forwarded());
        assert_eq!(&out[..6], &dmac.octets());
        assert_eq!(&out[6..12], &SRC.octets());
        assert_eq!(out[12..], packet[12..]);
        assert_eq!(cb[2], 0);
    }
}

#[test]
fn off_link_uses_the_live_gateway_mac_and_on_link_keeps_its_neighbour() {
    let mut root = load_egress_root_with(binding());
    let prog = &root.skel.progs.tc_wan_egress_root;
    let neighbours = &root.skel.maps.ip_mac_v4;
    let cached = MacAddr(2, 1, 2, 3, 4, 5);
    let replacement = MacAddr(2, 5, 4, 3, 2, 1);
    insert_ip_mac_v4(neighbours, PEER, PEER_MAC, SRC, IFINDEX);
    let word = &mut root.skel.maps.bss_data.as_deref_mut().unwrap().confirmed_gateway_mac;
    for mac in [cached, replacement] {
        let mut bytes = [0; 8];
        bytes[..6].copy_from_slice(&mac.octets());
        *word = u64::from_ne_bytes(bytes);
        for (dst, expected) in [(REMOTE, mac), (PEER, PEER_MAC)] {
            let pkt = simple_ipv4_tcp(LAN_HOST, dst);
            let (_, out, cb) = run_prog_with_ctx(prog, &pkt, forwarded());
            assert_eq!(&out[..6], &expected.octets());
            assert_eq!(&out[6..12], &SRC.octets());
            assert_eq!(out[12..], pkt[12..]);
            assert_eq!(cb[2], 0);
        }
        // The second confirmation must also take priority over a stale neighbour.
        insert_ip_mac_v4(neighbours, GATEWAY, GW_MAC, SRC, IFINDEX);
        let packet_to_gateway = simple_ipv4_tcp(LAN_HOST, GATEWAY);
        let (_, out, _) = run_prog_with_ctx(prog, &packet_to_gateway, forwarded());
        assert_eq!(&out[..6], &GW_MAC.octets());
    }
    *word = 0;
    let (_, out, cb) = run_prog_with_ctx(prog, &simple_ipv4_tcp(LAN_HOST, REMOTE), forwarded());
    assert_eq!(&out[..6], &GW_MAC.octets());
    assert_eq!(cb[2], 0);
}

#[test]
fn prefix_boundaries_and_missing_gateway_reach_the_exit_with_the_selected_next_hop() {
    let (_backing, obj) = OwnedOpenObject::new();
    let exit = TcWanEgressExitSkelBuilder::default().open(obj).unwrap().load().unwrap();
    let zero = Ipv4Addr::UNSPECIFIED;
    for (mask, gateway, dst, expected) in [
        ([0; 4], GATEWAY, REMOTE, REMOTE),
        ([255, 255, 255, 254], GATEWAY, PEER, PEER),
        ([255; 4], GATEWAY, PEER, GATEWAY),
        ([255; 4], zero, REMOTE, zero),
        ([255, 255, 255, 0], GATEWAY, Ipv4Addr::new(192, 0, 2, 255), zero),
    ] {
        let root = load_egress_root_with(wan_egress_binding {
            wan_mask4: u32::from_ne_bytes(mask),
            gateway_ip4: u32::from_ne_bytes(gateway.octets()),
            ..binding()
        });
        wire_stage(
            &root.skel.maps.tc_pipe_exits_wan_egress,
            0,
            &exit.progs.tc_wan_egress_exit_redirect,
        );
        let pkt = simple_ipv4_tcp(LAN_HOST, dst);
        let (ret, out, cb) =
            run_prog_with_ctx(&root.skel.progs.tc_wan_egress_root, &pkt, forwarded());
        assert_eq!(ret, 7);
        assert_eq!(out, pkt);
        assert_eq!(&cb[2..], &[0x4e483452, u32::from_ne_bytes(expected.octets()), IFINDEX]);
    }
}

#[test]
fn only_forwarded_unicast_ethernet_ipv4_uses_neighbour_resolution() {
    let pkt = simple_ipv4_tcp(LAN_HOST, REMOTE);
    let mut multicast = pkt.clone();
    multicast[30..34].copy_from_slice(&[224, 0, 0, 1]);
    let vif = v6_tcp_syn_mss(1460);
    for (cfg, packet, ctx) in [
        (wan_egress_binding { is_pppoe: 1, ..binding() }, &pkt, forwarded()),
        (wan_egress_binding { has_l2: 0, ..binding() }, &pkt, forwarded()),
        (binding(), &pkt, TestSkb { mark: host_direct_mark(9), ..forwarded() }),
        (binding(), &pkt, TestSkb { ifindex: IFINDEX, ..Default::default() }),
        (binding(), &multicast, forwarded()),
        (binding(), &vif, forwarded()),
    ] {
        let root = load_egress_root_with(cfg);
        let (_, out, cb) = run_prog_with_ctx(&root.skel.progs.tc_wan_egress_root, packet, ctx);
        assert_eq!(out, *packet);
        assert_eq!(cb[2], 0);
    }
}

fn binding6() -> wan_egress_binding {
    wan_egress_binding {
        ifindex: IFINDEX,
        has_l2: 1,
        has_ipv6: 1,
        wan_ip6: WAN6.octets(),
        wan_mask6: {
            let mut mask = [0u8; 16];
            mask[..8].fill(0xff);
            mask
        },
        gateway_ip6: GATEWAY6.octets(),
        source_mac: SRC.octets(),
        ..Default::default()
    }
}

fn set_confirmed6(root: &mut EgressRoot, mac: MacAddr) {
    let mut bytes = [0u8; 8];
    bytes[..6].copy_from_slice(&mac.octets());
    root.skel.maps.bss_data.as_deref_mut().unwrap().confirmed_gateway_mac6 =
        u64::from_ne_bytes(bytes);
}

#[test]
fn v6_off_link_uses_the_confirmed_gateway_mac_and_on_link_keeps_neighbours() {
    let mut root = load_egress_root_with(binding6());
    set_confirmed6(&mut root, GW6_MAC);
    let prog = &root.skel.progs.tc_wan_egress_root;
    for (dst, expected) in [(REMOTE6, GW6_MAC), (PEER6, MacAddr::zero())] {
        let packet = simple_ipv6_tcp_syn(V6_SRC, dst);
        let (_, out, cb) = run_prog_with_ctx(prog, &packet, forwarded());
        if expected.is_zero() {
            assert_eq!(out, packet, "on-link dst={dst}");
        } else {
            assert_eq!(&out[..6], &expected.octets());
            assert_eq!(&out[6..12], &SRC.octets());
            assert_eq!(out[12..], packet[12..]);
        }
        assert_eq!(cb[2], 0);
    }
}

#[test]
fn v6_rewrite_requires_a_forwarded_frame_and_a_confirmed_mac() {
    let pkt = simple_ipv6_tcp_syn(V6_SRC, REMOTE6);
    let multicast = simple_ipv6_tcp_syn(V6_SRC, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    // No confirmed MAC: the mirror/route stage result is kept.
    let unresolved = load_egress_root_with(binding6());
    let (_, out, cb) =
        run_prog_with_ctx(&unresolved.skel.progs.tc_wan_egress_root, &pkt, forwarded());
    assert_eq!(out, pkt);
    assert_eq!(cb[2], 0);
    for (cfg, packet, ctx) in [
        // Not forwarded or host-direct: kernel paths keep their header.
        (binding6(), &pkt, TestSkb { ifindex: IFINDEX, ..Default::default() }),
        (binding6(), &pkt, TestSkb { mark: host_direct_mark(9), ..forwarded() }),
        // No IPv6 binding: the frame passes untouched.
        (binding(), &pkt, forwarded()),
        // Multicast destinations are not gateway traffic.
        (binding6(), &multicast, forwarded()),
    ] {
        let mut root = load_egress_root_with(cfg);
        set_confirmed6(&mut root, GW6_MAC);
        let (_, out, cb) = run_prog_with_ctx(&root.skel.progs.tc_wan_egress_root, packet, ctx);
        assert_eq!(out, *packet);
        assert_eq!(cb[2], 0);
    }
}
