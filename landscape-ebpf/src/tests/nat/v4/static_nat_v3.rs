use super::common::*;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use libbpf_rs::{MapCore, MapFlags};

    use super::*;
    use crate::tests::helper::map::as_bytes;

    const TC_ACT_SHOT: i32 = 2;

    const WAN_PORT_TCP: u16 = 8080;
    const LAN_PORT_TCP: u16 = 80;
    const WAN_PORT_UDP: u16 = 5353;
    const LAN_PORT_UDP: u16 = 53;

    fn tcp_ingress_lan_host_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, LAN_HOST, LAN_PORT_TCP, WAN_PORT_TCP);
            seed_static_ct(skel, PROTO_TCP, LAN_HOST, LAN_PORT_TCP, WAN_PORT_TCP, REMOTE_IP, 9999);

            let pkt = tcp_pkt(REMOTE_IP, WAN_IP, 9999, WAN_PORT_TCP, false);
            let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
            assert_eq!(ret, 0, "ingress should return TC_ACT_OK(0)");
            assert_eq!(parse_ipv4_dst(&out), LAN_HOST, "dst_ip should be rewritten to LAN host");
            assert_eq!(parse_tcp_ports(&out).1, LAN_PORT_TCP, "dst_port should be 80");
        });
    }

    #[test]
    fn tcp_ingress_lan_host_v3() {
        tcp_ingress_lan_host_v4();
    }

    fn tcp_egress_lan_host_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, LAN_HOST, LAN_PORT_TCP, WAN_PORT_TCP);
            seed_static_ct(skel, PROTO_TCP, LAN_HOST, LAN_PORT_TCP, WAN_PORT_TCP, REMOTE_IP, 9999);

            let pkt = tcp_pkt(LAN_HOST, REMOTE_IP, LAN_PORT_TCP, 9999, false);
            let (ret, out) = run(&skel.progs.tc_v4_from_lan, &pkt);
            assert_eq!(ret, -1, "egress should return TC_ACT_UNSPEC(-1)");
            assert_eq!(parse_ipv4_src(&out), WAN_IP, "src_ip should be rewritten to WAN IP");
            assert_eq!(parse_tcp_ports(&out).0, WAN_PORT_TCP, "src_port should be 8080");
        });
    }

    #[test]
    fn tcp_egress_lan_host_v3() {
        tcp_egress_lan_host_v4();
    }

    fn tcp_ingress_local_router_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, Ipv4Addr::UNSPECIFIED, LAN_PORT_TCP, WAN_PORT_TCP);
            seed_static_ct(skel, PROTO_TCP, WAN_IP, LAN_PORT_TCP, WAN_PORT_TCP, REMOTE_IP, 9999);

            let pkt = tcp_pkt(REMOTE_IP, WAN_IP, 9999, WAN_PORT_TCP, false);
            let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
            assert_eq!(ret, 0, "ingress should return TC_ACT_OK(0)");
            assert_eq!(
                parse_ipv4_dst(&out),
                WAN_IP,
                "dst_ip should stay WAN_IP, not 0.0.0.0 (OK path passthrough)"
            );
            assert_eq!(parse_tcp_ports(&out).1, LAN_PORT_TCP, "dst_port should be 80");
        });
    }

    #[test]
    fn tcp_ingress_local_router_v3() {
        tcp_ingress_local_router_v4();
    }

    fn tcp_ingress_local_router_create_path_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, Ipv4Addr::UNSPECIFIED, LAN_PORT_TCP, WAN_PORT_TCP);

            let pkt = tcp_pkt(REMOTE_IP, WAN_IP, 443, WAN_PORT_TCP, true);
            let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
            assert_eq!(ret, 0, "ingress should return TC_ACT_OK(0)");
            assert_eq!(parse_ipv4_dst(&out), WAN_IP, "dst_ip should stay WAN_IP, not 0.0.0.0");
            assert_eq!(parse_tcp_ports(&out).1, LAN_PORT_TCP, "dst_port should be 80");

            let key = ct_key(WAN_IP, LAN_PORT_TCP, REMOTE_IP, 443, PROTO_TCP);
            let value = skel.maps.napt_ct.lookup(as_bytes(&key), MapFlags::ANY).unwrap();
            let value = value.expect("ingress should create CT");
            assert_eq!(value[2], 1, "CT must be marked static");
        });
    }

    #[test]
    fn tcp_ingress_local_router_v3_create_path_preserves_dst_ip() {
        tcp_ingress_local_router_create_path_v4();
    }

    fn tcp_egress_local_router_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, Ipv4Addr::UNSPECIFIED, LAN_PORT_TCP, WAN_PORT_TCP);
            seed_static_ct(skel, PROTO_TCP, WAN_IP, LAN_PORT_TCP, WAN_PORT_TCP, REMOTE_IP, 9999);

            let pkt = tcp_pkt(WAN_IP, REMOTE_IP, LAN_PORT_TCP, 9999, false);
            let (ret, out) = run(&skel.progs.tc_v4_from_lan, &pkt);
            assert_eq!(ret, -1, "egress should return TC_ACT_UNSPEC(-1)");
            assert_eq!(parse_tcp_ports(&out).0, WAN_PORT_TCP, "src_port should be 8080");
        });
    }

    #[test]
    fn tcp_egress_local_router_v3() {
        tcp_egress_local_router_v4();
    }

    fn udp_ingress_local_router_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_UDP, Ipv4Addr::UNSPECIFIED, LAN_PORT_UDP, WAN_PORT_UDP);
            seed_static_ct(skel, PROTO_UDP, WAN_IP, LAN_PORT_UDP, WAN_PORT_UDP, REMOTE_IP, 12345);

            let pkt = udp_pkt(REMOTE_IP, WAN_IP, 12345, WAN_PORT_UDP);
            let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
            assert_eq!(ret, 0, "ingress should return TC_ACT_OK(0)");
            assert_eq!(parse_udp(&out).dport, LAN_PORT_UDP, "dst_port should be 53");
        });
    }

    #[test]
    fn udp_ingress_local_router_v3() {
        udp_ingress_local_router_v4();
    }

    fn udp_egress_local_router_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_UDP, Ipv4Addr::UNSPECIFIED, LAN_PORT_UDP, WAN_PORT_UDP);
            seed_static_ct(skel, PROTO_UDP, WAN_IP, LAN_PORT_UDP, WAN_PORT_UDP, REMOTE_IP, 12345);

            let pkt = udp_pkt(WAN_IP, REMOTE_IP, LAN_PORT_UDP, 12345);
            let (ret, out) = run(&skel.progs.tc_v4_from_lan, &pkt);
            assert_eq!(ret, -1, "egress should return TC_ACT_UNSPEC(-1)");
            assert_eq!(parse_udp(&out).sport, WAN_PORT_UDP, "src_port should be 5353");
        });
    }

    #[test]
    fn udp_egress_local_router_v3() {
        udp_egress_local_router_v4();
    }

    fn tcp_ingress_no_match_drop_v4() {
        with_skel(&[], &[], &[], |skel| {
            seed_static(skel, PROTO_TCP, Ipv4Addr::UNSPECIFIED, LAN_PORT_TCP, WAN_PORT_TCP);

            let pkt = tcp_pkt(REMOTE_IP, WAN_IP, 9999, 9090, false);
            let (ret, _) = run(&skel.progs.tc_v4_from_wan, &pkt);
            assert_eq!(ret, TC_ACT_SHOT, "ingress with no matching mapping should drop");
        });
    }

    #[test]
    fn tcp_ingress_no_match_drop_v3() {
        tcp_ingress_no_match_drop_v4();
    }
}
