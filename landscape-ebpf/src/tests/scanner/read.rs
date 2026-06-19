use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};

use crate::tests::test_skb_read_skel::types::skb_read_test_result;
use crate::tests::test_skb_read_skel::TestSkbReadSkelBuilder;

use super::package::*;

unsafe impl plain::Plain for skb_read_test_result {}

const MAP_KEY: u32 = 0;

fn run_skb_read(payload: &mut Vec<u8>) -> Option<skb_read_test_result> {
    let builder = TestSkbReadSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();

    let skel = open.load().unwrap();
    let prog = skel.progs.test_skb_read;

    let input = ProgramInput { data_in: Some(payload), ..Default::default() };

    let run_result = prog.test_run(input).expect("test_run failed");
    println!("return={} duration={:?}", run_result.return_value as i32, run_result.duration);

    let bytes =
        skel.maps.skb_read_test_map.lookup(&MAP_KEY.to_le_bytes(), MapFlags::ANY).ok().flatten()?;

    Some(*plain::from_bytes::<skb_read_test_result>(&bytes).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TC_ACT_OK: i32 = 0;

    const TC_ACT_UNSPEC: i32 = -1;

    fn assert_v4_ok(r: &skb_read_test_result) {
        assert_eq!(r.l3_proto, 4);
        assert_eq!(r.scan_ret, 0, "scan_ret={}", r.scan_ret);
        assert_eq!(r.read_l3_ret, TC_ACT_OK, "read_l3_ret={}", r.read_l3_ret);
        assert_eq!(r.read_info_ret, TC_ACT_OK, "read_info_ret={}", r.read_info_ret);
    }
    fn assert_v6_ok(r: &skb_read_test_result) {
        assert_eq!(r.l3_proto, 6);
        assert_eq!(r.scan_ret, 0, "scan_ret={}", r.scan_ret);
        assert_eq!(r.read_l3_ret, TC_ACT_OK, "read_l3_ret={}", r.read_l3_ret);
        assert_eq!(r.read_info_ret, TC_ACT_OK, "read_info_ret={}", r.read_info_ret);
    }

    fn pv4(r: &skb_read_test_result) {
        println!(
            "v4 scan={} read_l3={} read_info={} saddr={:#x} daddr={:#x} sport={} dport={}",
            r.scan_ret,
            r.read_l3_ret,
            r.read_info_ret,
            r.v4_l3_saddr,
            r.v4_l3_daddr,
            r.v4_info.src_port,
            r.v4_info.dst_port
        );
    }
    fn pv6(r: &skb_read_test_result) {
        let saddr = unsafe { r.v6_info.src_addr.all };
        let daddr = unsafe { r.v6_info.dst_addr.all };
        println!(
            "v6 scan={} read_l3={} read_info={} saddr={:08x}:{:08x}:{:08x}:{:08x} daddr={:08x}:{:08x}:{:08x}:{:08x} sport={} dport={}",
            r.scan_ret,
            r.read_l3_ret,
            r.read_info_ret,
            saddr[0], saddr[1], saddr[2], saddr[3],
            daddr[0], daddr[1], daddr[2], daddr[3],
            r.v6_info.src_port,
            r.v6_info.dst_port
        );
    }

    // ── v4 tests ──

    /// IPv4 TCP: 192.168.1.1:21 -> 192.168.1.2:1234
    #[test]
    fn skb_read_v4_tcp() {
        let mut pkt = build_ipv4_tcp_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(r.v4_info.src_addr.addr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_info.dst_addr.addr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(u16::from_be(r.v4_info.src_port), 21);
        assert_eq!(u16::from_be(r.v4_info.dst_port), 1234);
    }

    /// IPv4 TCP SYN
    #[test]
    fn skb_read_v4_tcp_syn() {
        let mut pkt = build_ipv4_tcp_syn_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(u16::from_be(r.v4_info.src_port), 21);
        assert_eq!(u16::from_be(r.v4_info.dst_port), 1234);
    }

    /// IPv4 TCP RST
    #[test]
    fn skb_read_v4_tcp_rst() {
        let mut pkt = build_ipv4_tcp_rst_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(u16::from_be(r.v4_info.src_port), 21);
        assert_eq!(u16::from_be(r.v4_info.dst_port), 1234);
    }

    /// IPv4 UDP: 10.0.0.1:5000 -> 10.0.0.2:6000
    #[test]
    fn skb_read_v4_udp() {
        let mut pkt = build_ipv4_udp_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [10, 0, 0, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(u16::from_be(r.v4_info.src_port), 5000);
        assert_eq!(u16::from_be(r.v4_info.dst_port), 6000);
    }

    /// IPv4 first fragment: IPs readable, ports readable
    #[test]
    fn skb_read_v4_frag_first() {
        let mut pkt = build_ipv4_frag_first_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(u16::from_be(r.v4_info.src_port), 21);
        assert_eq!(u16::from_be(r.v4_info.dst_port), 1234);
    }

    /// IPv4 non-first fragment: IPs readable, ports skipped (fragment_type >= FRAG_MIDDLE)
    #[test]
    fn skb_read_v4_frag_nonfirst() {
        let mut pkt = build_ipv4_frag_nonfirst_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);
        // deep read returns OK but ports stay at 0 because non-first fragment has no L4
        assert_eq!(r.v4_info.src_port, 0);
        assert_eq!(r.v4_info.dst_port, 0);
    }

    /// IPv4 ICMP echo: 192.168.1.1 -> 192.168.1.2, ports = echo id (0)
    #[test]
    fn skb_read_v4_icmp_echo() {
        let mut pkt = build_icmpv4_echo_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [192, 168, 1, 1]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [192, 168, 1, 2]);
        assert_eq!(r.v4_info.src_port, 0);
        assert_eq!(r.v4_info.dst_port, 0);
    }

    /// IPv4 ICMP error: outer 8.8.8.8 -> 10.0.0.1, inner 10.0.0.1:1234 -> 10.0.0.2:4321
    /// src flipped to inner daddr (10.0.0.2), ports from inner UDP (1234,4321)
    #[test]
    fn skb_read_v4_icmp_error() {
        let mut pkt = build_icmpv4_error_with_inner_ipv4_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv4(&r);
        assert_v4_ok(&r);

        // shallow read: outer IPs
        assert_eq!(r.v4_l3_saddr.to_ne_bytes(), [8, 8, 8, 8]);
        assert_eq!(r.v4_l3_daddr.to_ne_bytes(), [10, 0, 0, 1]);

        // deep read: src flipped to inner daddr (10.0.0.2)
        assert_eq!(r.v4_info.src_addr.addr.to_ne_bytes(), [10, 0, 0, 2]);
        assert_eq!(r.v4_info.dst_addr.addr.to_ne_bytes(), [10, 0, 0, 1]);
        // inner UDP ports (flipped: dst_port=source, src_port=dest)
        assert_eq!(u16::from_be(r.v4_info.dst_port), 1234);
        assert_eq!(u16::from_be(r.v4_info.src_port), 4321);
    }

    // ── v6 tests ──

    /// IPv6 TCP: 2001:db8:1::1:21 -> 2001:db8:1::2:1234
    #[test]
    fn skb_read_v6_tcp() {
        let mut pkt = build_ipv6_tcp_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);

        let expected_saddr =
            [0x20010db8u32.to_be(), 0x00010000u32.to_be(), 0, 0x00000001u32.to_be()];
        let expected_daddr =
            [0x20010db8u32.to_be(), 0x00010000u32.to_be(), 0, 0x00000002u32.to_be()];
        assert_eq!(r.v6_l3_saddr, expected_saddr);
        assert_eq!(r.v6_l3_daddr, expected_daddr);
        let saddr = unsafe { r.v6_info.src_addr.all };
        let daddr = unsafe { r.v6_info.dst_addr.all };
        assert_eq!(saddr, expected_saddr);
        assert_eq!(daddr, expected_daddr);
        assert_eq!(u16::from_be(r.v6_info.src_port), 21);
        assert_eq!(u16::from_be(r.v6_info.dst_port), 1234);
    }

    /// IPv6 UDP: 2001:db8:1::1:5000 -> 2001:db8:1::2:6000
    #[test]
    fn skb_read_v6_udp() {
        let mut pkt = build_ipv6_udp_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);

        let expected_saddr =
            [0x20010db8u32.to_be(), 0x00010000u32.to_be(), 0, 0x00000001u32.to_be()];
        assert_eq!(r.v6_l3_saddr, expected_saddr);
        assert_eq!(u16::from_be(r.v6_info.src_port), 5000);
        assert_eq!(u16::from_be(r.v6_info.dst_port), 6000);
    }

    /// IPv6 + Hop-by-Hop + UDP: 2001:db8:1::1:5000 -> 2001:db8:1::2:6000
    #[test]
    fn skb_read_v6_hop_udp() {
        let mut pkt = build_ipv6_hop_udp_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);

        let expected_saddr =
            [0x20010db8u32.to_be(), 0x00010000u32.to_be(), 0, 0x00000001u32.to_be()];
        assert_eq!(r.v6_l3_saddr, expected_saddr);
        assert_eq!(u16::from_be(r.v6_info.src_port), 5000);
        assert_eq!(u16::from_be(r.v6_info.dst_port), 6000);
    }

    /// IPv6 first fragment: IPs readable, ports readable from ICMP
    #[test]
    fn skb_read_v6_frag_first() {
        let mut pkt = build_ipv6_frag_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);

        let expected_saddr =
            [0x20010db8u32.to_be(), 0x00010000u32.to_be(), 0, 0x00000001u32.to_be()];
        assert_eq!(r.v6_l3_saddr, expected_saddr);
        // first fragment has L4 accessible
        assert_ne!(r.v6_info.src_port, 0);
    }

    /// IPv6 non-first fragment: IPs readable, ports skipped
    #[test]
    fn skb_read_v6_frag_nonfirst() {
        let mut pkt = build_ipv6_frag_nonfirst_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);
        assert_eq!(r.v6_info.src_port, 0);
        assert_eq!(r.v6_info.dst_port, 0);
    }

    /// IPv6 ICMP error: outer 2001:db8::ff -> inner_src, inner src -> dst UDP 1234->4321
    /// src flipped to inner daddr, ports from inner UDP
    #[test]
    fn skb_read_v6_icmp_error() {
        let mut pkt = build_icmpv6_error_with_inner_ipv6_eth();
        let r = run_skb_read(&mut pkt).expect("no result");
        pv6(&r);
        assert_v6_ok(&r);

        // shallow: outer src (router 2001:db8::ff), outer dst = inner_src (2001:db8::1:1)
        let outer_src = [
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0,
            0,
            u32::from_ne_bytes([0x00, 0x00, 0x00, 0xff]),
        ];
        let outer_dst = [
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0,
            0,
            u32::from_ne_bytes([0x00, 0x01, 0x00, 0x01]),
        ];
        assert_eq!(r.v6_l3_saddr, outer_src);
        assert_eq!(r.v6_l3_daddr, outer_dst);

        // deep: src flipped to inner daddr (2001:db8::1:2)
        let inner_dst = [
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0,
            0,
            u32::from_ne_bytes([0x00, 0x01, 0x00, 0x02]),
        ];
        let saddr = unsafe { r.v6_info.src_addr.all };
        let daddr = unsafe { r.v6_info.dst_addr.all };
        assert_eq!(saddr, inner_dst);
        assert_eq!(daddr, outer_dst);
        // inner UDP ports flipped
        assert_eq!(u16::from_be(r.v6_info.dst_port), 1234);
        assert_eq!(u16::from_be(r.v6_info.src_port), 4321);
    }

    // ── edge cases ──

    /// ARP should not be classified as IP; all return codes = -1
    #[test]
    fn skb_read_arp() {
        let mut pkt = vec![
            0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x08, 0x06,
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            192, 168, 1, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 192, 168, 1, 2,
        ];
        let r = run_skb_read(&mut pkt).expect("no result");
        assert_eq!(r.l3_proto, 0);
        assert_eq!(r.scan_ret, TC_ACT_UNSPEC);
        assert_eq!(r.read_l3_ret, TC_ACT_UNSPEC);
        assert_eq!(r.read_info_ret, TC_ACT_UNSPEC);
    }
}
