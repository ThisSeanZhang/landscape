use std::{
    mem::MaybeUninit,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    process::Command,
    time::Duration,
};

use etherparse::PacketBuilder;
use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::maps::Inet6Bytes;
use crate::skel::tproxy::TproxySkelBuilder;
use crate::tests::{
    helper::net::{NetNsGuard, TCAttach, VethPair, send_raw_packet},
    helper::wire::TproxyPacketTestResult,
    pkt::{
        build_icmpv4_echo_eth, build_ipv4_tcp_eth, build_ipv4_udp_eth, build_ipv6_tcp_eth,
        build_ipv6_udp_eth,
    },
    test_tproxy_packet::TestTproxyPacketSkelBuilder,
};
use zerocopy::FromBytes;

const MAP_KEY: u32 = 0;

// `tproxy_ingress` cannot be exercised through `BPF_PROG_TEST_RUN`: the
// kernel's `convert___skb_to_skb()` rejects non-zero `vlan_present` / `vlan_tci`
// in `ctx_in`, so the landscape VLAN tag cannot be injected. These tests cover
// the packet parser; ingress-level VLAN behaviour is covered by the ignored
// live TC/veth test at the bottom of this file.

fn run_tproxy_packet_test(payload: Vec<u8>) -> TproxyPacketTestResult {
    let builder = TestTproxyPacketSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    skel.progs
        .test_tproxy_packet
        .test_run(ProgramInput { data_in: Some(&payload), ..Default::default() })
        .expect("test_run failed");

    let result = skel
        .maps
        .tproxy_packet_test_result_map
        .lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY)
        .unwrap()
        .unwrap();
    TproxyPacketTestResult::read_from_bytes(&result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_OK: i32 = 0;
    const TC_ACT_UNSPEC: i32 = -1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_UDP: u8 = 17;
    const LANDSCAPE_IPV4_TYPE: u8 = 0;
    const LANDSCAPE_IPV6_TYPE: u8 = 1;

    #[test]
    fn tproxy_packet_ipv4_tcp() {
        let result = run_tproxy_packet_test(build_ipv4_tcp_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV4_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_TCP);
        assert_eq!(Ipv4Addr::from(result.pair.src_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Ipv4Addr::from(result.pair.dst_addr.ipv4()), Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(u16::from_be(result.pair.src_port), 21);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_ipv4_udp() {
        let result = run_tproxy_packet_test(build_ipv4_udp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_ipv6_tcp() {
        let result = run_tproxy_packet_test(build_ipv6_tcp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_TCP);
        assert_eq!(
            Ipv6Addr::from(result.pair.src_addr),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            Ipv6Addr::from(result.pair.dst_addr),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 2)
        );
        assert_eq!(u16::from_be(result.pair.src_port), 21);
        assert_eq!(u16::from_be(result.pair.dst_port), 1234);
    }

    #[test]
    fn tproxy_packet_ipv6_udp() {
        let result = run_tproxy_packet_test(build_ipv6_udp_eth());
        assert_eq!(result.read_ret, TC_ACT_OK);
        assert_eq!(result.view.l3_protocol, LANDSCAPE_IPV6_TYPE);
        assert_eq!(result.view.l4_protocol, IPPROTO_UDP);
        assert_eq!(u16::from_be(result.pair.src_port), 5000);
        assert_eq!(u16::from_be(result.pair.dst_port), 6000);
    }

    #[test]
    fn tproxy_packet_icmpv4_classified_without_inner_parse() {
        let result = run_tproxy_packet_test(build_icmpv4_echo_eth());
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_UNSPEC);
        assert_eq!(result.view.l4_protocol, IPPROTO_ICMP);
    }

    #[test]
    fn tproxy_packet_unsupported_protocol_returns_unspec() {
        let mut pkt = build_icmpv4_echo_eth();
        pkt[14 + 9] = 47;
        let result = run_tproxy_packet_test(pkt);
        assert_eq!(result.scan_ret, TC_ACT_OK);
        assert_eq!(result.read_ret, TC_ACT_UNSPEC);
        assert_eq!(result.view.l4_protocol, 47);
    }
}

/// Live TC/veth coverage for the ingress hook. `BPF_PROG_TEST_RUN` cannot
/// inject `vlan_tci`, so a peer egress program pushes a real 802.1Q tag into
/// skb metadata before the frame crosses the veth. The host ingress program
/// must pop that tag, classify the UDP flow, and assign the packet to the
/// proxy's bound socket.
#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tproxy_ingress_vlan_tag_assigns_udp_socket() {
    const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const CLIENT_PORT: u16 = 40000;
    const REMOTE_PORT: u16 = 53;

    let test_ns = NetNsGuard::create("tpt");
    let peer_ns = NetNsGuard::create("tptp");
    let pair = {
        let _e = test_ns.enter();
        VethPair::create_with_netns("tpt", &peer_ns)
    };
    {
        let _e = test_ns.enter();
        Command::new("ip")
            .args(["link", "set", "dev", pair.host(), "address", "02:00:00:00:00:01"])
            .output()
            .unwrap();
        Command::new("ip")
            .args(["addr", "add", "10.0.0.1/24", "dev", pair.host()])
            .output()
            .unwrap();
    }
    {
        let _e = peer_ns.enter();
        Command::new("ip")
            .args(["link", "set", "dev", pair.peer(), "address", "02:00:00:00:00:02"])
            .output()
            .unwrap();
        Command::new("ip")
            .args(["addr", "add", "10.0.0.2/24", "dev", pair.peer()])
            .output()
            .unwrap();
    }

    let server = {
        let _e = test_ns.enter();
        let sock = UdpSocket::bind((HOST_IP, 0)).expect("bind proxy UDP socket");
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock
    };
    let proxy_port = server.local_addr().unwrap().port();

    let pin_root = crate::tests::isolated_pin_root("tproxy-live");
    let mut builder = TproxySkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = MaybeUninit::uninit();
    let mut open = builder.open(&mut open_object).unwrap();
    {
        let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.proxy_addr = u32::from_ne_bytes(HOST_IP.octets());
        rodata.proxy_port = proxy_port.to_be();
        rodata.enable_icmp_passthrough = false;
    }
    let skel = open.load().unwrap();

    let mut push_builder = TestTproxyPacketSkelBuilder::default();
    push_builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut push_object = MaybeUninit::uninit();
    let push_skel = push_builder.open(&mut push_object).unwrap().load().unwrap();

    let _attach;
    let _push;
    {
        let _e = test_ns.enter();
        _attach = TCAttach::attach_ingress(&skel.progs.tproxy_ingress, pair.host_ifindex() as i32);
    }
    {
        let _e = peer_ns.enter();
        _push = TCAttach::attach_egress(
            &push_skel.progs.test_tproxy_vlan_push,
            pair.peer_ifindex() as i32,
        );
    }

    let inner = PacketBuilder::ethernet2(PEER_MAC, HOST_MAC)
        .ipv4(PEER_IP.octets(), HOST_IP.octets(), 64)
        .udp(CLIENT_PORT, REMOTE_PORT);
    let payload = [0xaa, 0xbb, 0xcc, 0xdd];
    let mut frame = Vec::with_capacity(inner.size(payload.len()));
    inner.write(&mut frame, &payload).unwrap();

    {
        let _e = peer_ns.enter();
        send_raw_packet(pair.peer(), &frame);
    }

    let mut buf = [0u8; 64];
    let (len, src) = server.recv_from(&mut buf).expect("tagged packet did not reach proxy socket");
    assert_eq!(&buf[..len], &payload);
    assert_eq!(src.ip(), PEER_IP);
    assert_eq!(src.port(), CLIENT_PORT);
}
