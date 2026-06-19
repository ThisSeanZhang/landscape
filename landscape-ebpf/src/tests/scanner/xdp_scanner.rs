use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::tests::test_xdp_scanner_skel::types::xdp_scan_test_result;
use crate::tests::test_xdp_scanner_skel::TestXdpScannerSkelBuilder;

use super::package::*;

unsafe impl plain::Plain for xdp_scan_test_result {}

const MAP_KEY: u32 = 0;

fn run_xdp_scanner(payload: &mut Vec<u8>) -> Option<xdp_scan_test_result> {
    let builder = TestXdpScannerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();

    let skel = open.load().unwrap();
    let prog = skel.progs.xdp_test_scanner;

    let input = ProgramInput { data_in: Some(payload), ..Default::default() };

    let run_result = prog.test_run(input).expect("test_run failed");
    println!("return={} duration={:?}", run_result.return_value as i32, run_result.duration);

    let bytes =
        skel.maps.xdp_scan_test_map.lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY).ok().flatten()?;

    Some(*plain::from_bytes::<xdp_scan_test_result>(&bytes).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──

    fn assert_v4_ok(r: &xdp_scan_test_result) {
        assert_eq!(r.l3_proto, 4);
        assert_eq!(r.scan_ret, 0, "scan_ret={}", r.scan_ret);
    }
    fn assert_v6_ok(r: &xdp_scan_test_result) {
        assert_eq!(r.l3_proto, 6);
        assert_eq!(r.scan_ret, 0, "scan_ret={}", r.scan_ret);
    }
    fn pv4(r: &xdp_scan_test_result) {
        let v = &r.v4;
        println!("v4 off={} proto={} frag_t={} frag_off={} frag_id={} pkt_t={} err_l3={} err_l4={} err_proto={}",
            v.l4_offset, v.l4_protocol, v.fragment_type, v.fragment_off, v.fragment_id,
            v.pkt_type, v.icmp_error_l3_offset, v.icmp_error_inner_l4_offset, v.icmp_error_l4_protocol);
    }
    fn pv6(r: &xdp_scan_test_result) {
        let v = &r.v6;
        println!("v6 off={} proto={} frag_t={} frag_off={} frag_id={} pkt_t={} err_l3={} err_l4={} err_proto={}",
            v.l4_offset, v.l4_protocol, v.fragment_type, v.fragment_off, v.fragment_id,
            v.pkt_type, v.icmp_error_l3_offset, v.icmp_error_inner_l4_offset, v.icmp_error_l4_protocol);
    }

    // ── v4 tests ──

    #[test]
    fn xdp_v4_tcp() {
        let mut pkt = build_ipv4_tcp_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        // build_ipv4_tcp_eth has no SYN flag set → PKT_TCP_DATA_V2=1
        assert_eq!(r.v4.l4_protocol, 6);
        assert_eq!(r.v4.l4_offset, 34);
        assert_eq!(r.v4.fragment_type, 0); // FRAG_SINGLE
        assert_eq!(r.v4.pkt_type, 1); // PKT_TCP_DATA_V2
    }

    #[test]
    fn xdp_v4_udp() {
        let mut pkt = build_ipv4_udp_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        assert_eq!(r.v4.l4_protocol, 17); // IPPROTO_UDP
        assert_eq!(r.v4.l4_offset, 34);
        assert_eq!(r.v4.fragment_type, 0);
        assert_eq!(r.v4.pkt_type, 0); // PKT_CONNLESS_V2
    }

    #[test]
    fn xdp_v4_frag_first() {
        let mut pkt = build_ipv4_frag_first_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        assert_eq!(r.v4.fragment_type, 1); // FRAG_FIRST
        assert_eq!(r.v4.fragment_id, 0x4242);
        assert_eq!(r.v4.fragment_off, 0);
        assert_eq!(r.v4.l4_protocol, 6); // TCP
    }

    #[test]
    fn xdp_v4_frag_nonfirst() {
        let mut pkt = build_ipv4_frag_nonfirst_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        assert_eq!(r.v4.fragment_type, 2); // FRAG_MIDDLE (MF=1, off!=0)
        assert_eq!(r.v4.fragment_id, 0x4242);
        assert_eq!(r.v4.fragment_off, 1); // offset=1 → 8-byte unit 1
        assert_eq!(r.v4.pkt_type, 0); // not set for non-first frag
    }

    #[test]
    fn xdp_v4_icmp_echo() {
        let mut pkt = build_icmpv4_echo_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        assert_eq!(r.v4.l4_protocol, 1); // IPPROTO_ICMP
        assert_eq!(r.v4.pkt_type, 0); // PKT_CONNLESS_V2
        assert_eq!(r.v4.icmp_error_l3_offset, 0);
    }

    #[test]
    fn xdp_v4_icmp_error() {
        let mut pkt = build_icmpv4_error_with_inner_ipv4_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        assert_eq!(r.v4.l4_protocol, 1); // ICMP
        assert_ne!(r.v4.icmp_error_l3_offset, 0);
        assert_ne!(r.v4.icmp_error_inner_l4_offset, 0);
        assert_eq!(r.v4.icmp_error_l4_protocol, 17); // inner UDP
    }

    // ── v6 tests ──

    #[test]
    fn xdp_v6_tcp() {
        let mut pkt = build_ipv6_tcp_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        assert_eq!(r.v6.l4_protocol, 6); // NEXTHDR_TCP
        assert_eq!(r.v6.l4_offset, 54); // eth(14) + ipv6(40)
        assert_eq!(r.v6.fragment_type, 0); // FRAG_SINGLE
        assert_eq!(r.v6.pkt_type, 1); // PKT_TCP_DATA_V2 (no SYN)
    }

    #[test]
    fn xdp_v6_frag_first() {
        let mut pkt = build_ipv6_frag_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        // raw bytes: nexthdr=NEXTHDR_FRAGMENT, inner=NEXTHDR_ICMP(58)
        assert_eq!(r.v6.fragment_type, 1); // FRAG_FIRST
        assert_eq!(r.v6.fragment_off, 0);
        assert_ne!(r.v6.fragment_id, 0); // has ID
        assert_eq!(r.v6.l4_protocol, 58); // NEXTHDR_ICMP
        assert_eq!(r.v6.pkt_type, 0); // ICMP → PKT_CONNLESS_V2
    }

    #[test]
    fn xdp_v6_udp() {
        let mut pkt = build_ipv6_udp_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        assert_eq!(r.v6.l4_protocol, 17); // NEXTHDR_UDP
        assert_eq!(r.v6.l4_offset, 54);
        assert_eq!(r.v6.fragment_type, 0);
        assert_eq!(r.v6.pkt_type, 0); // PKT_CONNLESS_V2
    }

    #[test]
    fn xdp_v6_icmp_error() {
        let mut pkt = build_icmpv6_error_with_inner_ipv6_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        assert_eq!(r.v6.l4_protocol, 58); // NEXTHDR_ICMP (ICMPv6)
        assert_ne!(r.v6.icmp_error_l3_offset, 0);
        assert_ne!(r.v6.icmp_error_inner_l4_offset, 0);
        assert_eq!(r.v6.icmp_error_l4_protocol, 17); // inner UDP
    }

    #[test]
    fn xdp_v6_frag_nonfirst() {
        let mut pkt = build_ipv6_frag_nonfirst_eth();
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        assert!(r.v6.fragment_type >= 2); // non-first
        assert!(r.v6.fragment_off > 0);
    }

    #[test]
    fn xdp_unsupported_arp() {
        let mut pkt = vec![
            0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            192, 168, 1, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 2,
        ];
        let r = run_xdp_scanner(&mut pkt).expect("no result");
        assert_eq!(r.l3_proto, 0); // XDP_L3_NONE
        assert_eq!(r.scan_ret, 0);
    }
}
