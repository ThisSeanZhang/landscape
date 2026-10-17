//! Pins the SKB-mode PPPoE fallback (`pppoe_skb_fallback.bpf.c`):
//! OUR sessions (published in the per-iface `pppoe_sessions` hash map)
//! are decapped (len−8, ethertype rewritten, mac pair preserved) and
//! passed for the TC ingress intro to dispatch by inner dst; everything
//! else passes untouched — pppd-owned sessions (coexistence), PPP
//! control protocols, and malformed frames.
//!
//! Run (needs root + the `bpf-test` feature):
//!   cargo test -p landscape-ebpf --features bpf-test --lib route::pppoe_skb_fallback -- --nocapture

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkelBuilder;
use crate::tests::pkt::{simple_pppoe_ipv4, simple_pppoe_ipv6};

const XDP_PASS: u32 = 2;

const SESS: u16 = 0x1234;
const FOREIGN_SESS: u16 = 0x9999;

const ETH_P_IPV4_BE: [u8; 2] = [0x08, 0x00];
const ETH_P_IPV6_BE: [u8; 2] = [0x86, 0xDD];

fn run(
    skel: &crate::skel::pppoe_skb_fallback::PppoeSkbFallbackSkel<'_>,
    pkt: &[u8],
) -> (u32, Vec<u8>) {
    let mut out_buf = vec![0u8; pkt.len().max(64) + 32];
    let out = skel
        .progs
        .pppoe_skb_fallback
        .test_run(ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out_buf),
            ..Default::default()
        })
        .expect("test_run pppoe_skb_fallback");
    (out.return_value, out.data.expect("data_out").to_vec())
}

#[test]
fn pppoe_skb_fallback_matrix() {
    let builder = PppoeSkbFallbackSkelBuilder::default();
    let mut obj = MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open fallback");
    let skel = open.load().expect("load fallback");

    skel.maps
        .pppoe_sessions
        .update(&SESS.to_ne_bytes(), &5u32.to_ne_bytes(), MapFlags::ANY)
        .expect("publish session");

    // our session, v4 payload → decap
    {
        let pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let (rv, out) = run(&skel, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "v4: 8-byte session header stripped");
        assert_eq!(&out[0..12], &pkt[0..12], "v4: mac pair preserved");
        assert_eq!(&out[12..14], &ETH_P_IPV4_BE, "v4: ethertype rewritten");
        assert_eq!(&out[14..], &pkt[22..], "v4: inner IP carried verbatim");
    }

    // our session, v6 payload → decap
    {
        let pkt = simple_pppoe_ipv6(
            SESS,
            Ipv6Addr::from_str("fd00::1").unwrap(),
            Ipv6Addr::from_str("fd44:5555::1").unwrap(),
        );
        let (rv, out) = run(&skel, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out.len(), pkt.len() - 8, "v6: stripped");
        assert_eq!(&out[0..12], &pkt[0..12]);
        assert_eq!(&out[12..14], &ETH_P_IPV6_BE, "v6: ethertype rewritten");
        assert_eq!(&out[14..], &pkt[22..]);
    }

    // pppd-owned session → untouched (coexistence)
    {
        let pkt = simple_pppoe_ipv4(
            FOREIGN_SESS,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(203, 0, 113, 7),
        );
        let (rv, out) = run(&skel, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out, pkt, "foreign session: untouched");
    }

    // PPP control protocol inside the session ethertype → untouched
    {
        let mut pkt =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        pkt[20..22].copy_from_slice(&[0xc0, 0x21]); // PPP protocol: LCP
        let (rv, out) = run(&skel, &pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out, pkt, "LCP control frame: untouched");
    }

    // malformed: truncated pppoe header → untouched
    {
        let full =
            simple_pppoe_ipv4(SESS, Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(203, 0, 113, 7));
        let pkt = &full[..18];
        let (rv, out) = run(&skel, pkt);
        assert_eq!(rv, XDP_PASS);
        assert_eq!(out, pkt, "truncated header: untouched");
    }
}
