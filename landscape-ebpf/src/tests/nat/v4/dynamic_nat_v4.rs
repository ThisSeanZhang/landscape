//! Dynamic NAT4-v4 scenarios ported from the retired v3 suite.
//!
//! Only cases that are not already covered by `tc_nat4_v4_behavior` /
//! `tc_nat4_v4_ct_timer` live here: the minimal TCP quote on ICMP errors for
//! both directions, and the ACTIVE-with-zero-refs ingress rejection.

use std::net::Ipv4Addr;

use super::common::*;

const TCP_NAT_PORT: u16 = 40000;
const TCP_REMOTE_PORT: u16 = 443;

const OUTER_IP_OFFSET: usize = 14;
const OUTER_ICMP_OFFSET: usize = OUTER_IP_OFFSET + 20;
const INNER_IP_OFFSET: usize = OUTER_ICMP_OFFSET + 8;
const INNER_TCP_OFFSET: usize = INNER_IP_OFFSET + 20;

fn seed_tcp_flow(skel: &crate::tests::tc_nat4_v4_skel::TcNat4V4Skel<'_>) {
    seed_dynamic(
        skel,
        PROTO_TCP,
        LAN_HOST,
        LAN_PORT,
        TCP_NAT_PORT,
        REMOTE_IP,
        TCP_REMOTE_PORT,
        1,
        0,
        1,
    );
    seed_dynamic_ct(
        skel,
        PROTO_TCP,
        LAN_HOST,
        LAN_PORT,
        TCP_NAT_PORT,
        REMOTE_IP,
        TCP_REMOTE_PORT,
        0,
        CT_ACTIVE,
    );
}

fn assert_min_tcp_quote(
    packet: &[u8],
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_source_port: u16,
    inner_dest_port: u16,
) {
    assert_eq!(&packet[INNER_IP_OFFSET + 12..INNER_IP_OFFSET + 16], &inner_src.octets());
    assert_eq!(&packet[INNER_IP_OFFSET + 16..INNER_IP_OFFSET + 20], &inner_dst.octets());
    assert_eq!(
        u16::from_be_bytes(packet[INNER_TCP_OFFSET..INNER_TCP_OFFSET + 2].try_into().unwrap()),
        inner_source_port
    );
    assert_eq!(
        u16::from_be_bytes(packet[INNER_TCP_OFFSET + 2..INNER_TCP_OFFSET + 4].try_into().unwrap()),
        inner_dest_port
    );
}

#[test]
fn tcp_egress_icmp_error_accepts_min_quote_v4() {
    with_skel(&[], &[], &[], |skel| {
        seed_tcp_flow(skel);

        let pkt =
            icmp_error_tcp_min(REMOTE_IP, LAN_HOST, TCP_REMOTE_PORT, LAN_PORT, LAN_HOST, REMOTE_IP);
        let (ret, out) = run(&skel.progs.tc_v4_from_lan, &pkt);
        assert_eq!(ret, -1);

        assert_eq!(parse_ipv4_src(&out), WAN_IP);
        assert_min_tcp_quote(&out, REMOTE_IP, WAN_IP, TCP_REMOTE_PORT, TCP_NAT_PORT);
    });
}

#[test]
fn tcp_ingress_icmp_error_accepts_min_quote_v4() {
    with_skel(&[], &[], &[], |skel| {
        seed_tcp_flow(skel);

        let pkt =
            icmp_error_tcp_min(WAN_IP, REMOTE_IP, TCP_NAT_PORT, TCP_REMOTE_PORT, REMOTE_IP, WAN_IP);
        let (ret, out) = run(&skel.progs.tc_v4_from_wan, &pkt);
        assert_eq!(ret, 0);

        assert_eq!(parse_ipv4_dst(&out), LAN_HOST);
        assert_min_tcp_quote(&out, LAN_HOST, REMOTE_IP, LAN_PORT, TCP_REMOTE_PORT);
    });
}

#[test]
fn tcp_ingress_active_zero_refs_blocks_new_ct_v4() {
    with_skel(&[], &[], &[], |skel| {
        seed_dynamic(
            skel,
            PROTO_TCP,
            LAN_HOST,
            LAN_PORT,
            TCP_NAT_PORT,
            REMOTE_IP,
            TCP_REMOTE_PORT,
            1,
            0,
            0,
        );

        let pkt = tcp_pkt(REMOTE_IP, WAN_IP, TCP_REMOTE_PORT, TCP_NAT_PORT, true);
        let (ret, _) = run(&skel.progs.tc_v4_from_wan, &pkt);
        assert_eq!(ret, 2, "ACTIVE mapping with zero refs must reject new ingress CT");
    });
}
