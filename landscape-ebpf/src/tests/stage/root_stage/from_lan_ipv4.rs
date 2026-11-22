use super::*;
use crate::skel::tc_wan_egress_exit::TcWanEgressExitSkelBuilder;
use crate::skel::tc_wan_egress_root::types::wan_egress_binding;
use crate::tests::helper::map::{host_direct_mark, insert_ip_mac_v4};
use crate::tests::pkt::simple_ipv4_tcp;
use landscape_common::net::MacAddr;

const IFINDEX: u32 = 1; // loopback in PROG_TEST_RUN
const WAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 8);
const SRC: MacAddr = MacAddr(2, 0, 0, 0, 0, 10);
const GW_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 1);
const PEER_MAC: MacAddr = MacAddr(2, 0, 0, 0, 0, 11);

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
