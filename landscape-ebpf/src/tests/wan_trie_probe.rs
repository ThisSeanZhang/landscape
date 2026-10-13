//! Differential test of the BPF-side `wan_trie` reader: Rust publishes the
//! entry set into the probe program's real arena through the mmap, then the
//! same case matrix as the pure-Rust builder tests is replayed through
//! `BPF_PROG_TEST_RUN` and compared against `reference_lpm` — proving the C
//! `wan_trie_resolve` walk and the `wan_trie_key_v4/ppp/ifx` byte-order
//! layouts agree with the userspace builder, on a real kernel.
//!
//! All packet payload fields are NETWORK byte order (payload byte j is trie
//! key byte j), mirroring how the production programs memcpy packet bytes
//! into the u64 key register.
//!
//! Run (needs root + the `bpf-test` feature):
//!   cargo test -p landscape-ebpf --features bpf-test --lib wan_trie_probe -- --nocapture

use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel as _, SkelBuilder as _},
};

use crate::maps::wan_trie::builder::tests::{d, p};
use crate::maps::wan_trie::builder::{
    PrefixEntry, ifx_entry, ppp_entry, reference_lpm, v4_entry, v6_entry, wan_trie_publish,
};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::tests::test_wan_trie_probe_skel::{TestWanTrieProbeSkel, TestWanTrieProbeSkelBuilder};

const MODE_RAW: u8 = 0;
const MODE_V4: u8 = 1;
const MODE_PPP: u8 = 2;
const MODE_IFX: u8 = 3;
const BAD_KEY: u32 = 0xFFFF_FFFF;

/// `[mode][7B pad][payload]`; payload bytes are already network order.
fn packet(mode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 8);
    let mut pkt = vec![0u8; 16];
    pkt[0] = mode;
    pkt[8..8 + payload.len()].copy_from_slice(payload);
    pkt
}

/// Publish `entries` into the probe program's arena via the mmap.
fn publish(skel: &mut TestWanTrieProbeSkel<'_>, entries: &[PrefixEntry]) {
    let data = skel.maps.wan_trie_arena_data.as_mut().expect("wan_trie arena mmap data");
    wan_trie_publish(cast_arena_tbl(&mut data.wan_trie_tbl), entries).expect("publish");
}

/// Resolve one request through the real C reader in the kernel.
fn resolve(skel: &mut TestWanTrieProbeSkel<'_>, pkt: &[u8]) -> u32 {
    let out = skel
        .progs
        .test_wan_trie_probe
        .test_run(ProgramInput { data_in: Some(pkt), ..Default::default() })
        .expect("test_run");
    out.return_value
}

#[test]
fn bpf_reader_matches_reference() {
    let builder = TestWanTrieProbeSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).expect("open test_wan_trie_probe");
    let mut skel = open.load().expect("load test_wan_trie_probe");

    // ── 1. every prefix length 0..=64 nested under a /40 umbrella
    //       (covers mid-byte plens through prefix expansion) ──
    for plen in 0..=64u8 {
        let entries = [
            p(&format!("fd22:2222:33ab:1234::/{plen}"), 7),
            p("fd22:2222:3300::/40", 4),
            p("fd44:5555:3300::/40", 5),
        ];
        publish(&mut skel, &entries);

        for dst in [
            d("fd22:2222:33ab:1234::1"),
            d("fd22:2222:33ab:1200::1"),
            d("fd22:2222:33ab:13ff::1"),
            d("fd99::1"),
        ] {
            assert_eq!(
                resolve(&mut skel, &packet(MODE_RAW, &dst)),
                reference_lpm(&entries, &dst),
                "plen {plen}, dst {dst:02x?}"
            );
        }
    }

    // ── 2. mixed-granularity nesting tower (byte-aligned + mid-byte) ──
    let entries = [
        p("fd22:2222::/32", 10),
        p("fd22:2222:3300::/40", 11),
        p("fd22:2222:33ab::/48", 12),      // b6 = *
        p("fd22:2222:33ab:0000::/52", 13), // b6 in [0x00, 0x0f]
        p("fd22:2222:33ab::/56", 14),      // b6 = 0x00, b7 = *
        p("fd22:2222:33ab:0040::/58", 19), // b7 in [0x40, 0x7f]
        p("fd22:2222:33ab:8000::/57", 15), // b6 = 0x80, b7 in [0x00, 0x7f]
        p("fd22:2222:33ab:9100::/58", 16), // b6 = 0x91, b7 in [0x00, 0x3f]
        p("fd22:2222:33ab:9120::/61", 17), // b7 in [0x20, 0x27]
        p("fd22:2222:33ab:9127::/64", 18),
    ];
    let cases = [
        (d("fd22:2222:33ab:9127::1"), 18), // exact /64
        (d("fd22:2222:33ab:9124::1"), 17), // b7 in [0x20, 0x27]
        (d("fd22:2222:33ab:913f::1"), 16), // b7 in [0x00, 0x3f], outside /61
        (d("fd22:2222:33ab:9140::1"), 12), // b7 outside /58: /48
        (d("fd22:2222:33ab:807f::1"), 15), // b6 = 0x80, b7 in [0x00, 0x7f]
        (d("fd22:2222:33ab:80ff::1"), 12), // b7 outside [0x00, 0x7f]: /48
        (d("fd22:2222:33ab:005f::1"), 19), // b6 = 0x00, b7 in [0x40, 0x7f]
        (d("fd22:2222:33ab:003f::1"), 14), // b7 in [0x00, 0x3f]: /56
        (d("fd22:2222:33ab:0f27::1"), 13), // b6 in [0x00, 0x0f]: /52
        (d("fd22:2222:33ab:1000::1"), 12), // b6 >= 0x10: /48
        (d("fd22:2222:33ab:7fff::1"), 12), // b6 outside every branch: /48
        (d("fd22:2222:33af::1"), 11),      // b5 != 0xab: /40
        (d("fd22:2222::1"), 10),           // b4 outside /40: /32
        (d("fd22:2223::1"), 0),            // outside everything: miss
    ];
    publish(&mut skel, &entries);
    for (dst, expect) in cases {
        assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &dst)), expect, "tower dst {dst:02x?}");
        assert_eq!(reference_lpm(&entries, &dst), expect);
    }

    // ── 3. namespaces + the BPF key helpers (network-order payloads) ──
    let entries = [
        v6_entry(Ipv6Addr::from_str("fd22:2222:33ab::").unwrap(), 48, 60).unwrap(),
        v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, 61).unwrap(), // 203.0.113.0/24
        ppp_entry(0x1234, 62),
        ifx_entry(7, 63),
    ];
    publish(&mut skel, &entries);

    // v6 prefix64 through the raw-key mode
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd22:2222:33ab::1"))), 60);
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd99::1"))), 0);

    // v4 daddr: payload 203.0.113.7 in network order
    assert_eq!(resolve(&mut skel, &packet(MODE_V4, &[203, 0, 113, 7])), 61);
    assert_eq!(resolve(&mut skel, &packet(MODE_V4, &[203, 0, 114, 7])), 0);

    // ppp session: payload 0x1234 big-endian
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0x12, 0x34])), 62);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0x12, 0x35])), 0);

    // ifindex: payload 7 big-endian; the helper takes host order and swaps
    // internally, mirroring how production feeds it ctx->ingress_ifindex
    assert_eq!(resolve(&mut skel, &packet(MODE_IFX, &[0, 0, 0, 7])), 63);
    assert_eq!(resolve(&mut skel, &packet(MODE_IFX, &[0, 0, 0, 8])), 0);

    // ── 4. republish flip drops stale entries (double buffering) ──
    publish(&mut skel, &[p("fd00::/16", 3)]);
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd00:1122::1"))), 3);

    publish(&mut skel, &[p("fd44::/16", 4)]);
    assert_eq!(
        resolve(&mut skel, &packet(MODE_RAW, &d("fd00:1122::1"))),
        0,
        "stale entry survived the flip"
    );
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd44::1"))), 4);

    // ── 5. malformed requests report the sentinel ──
    assert_eq!(resolve(&mut skel, &[0u8; 14]), BAD_KEY);
    assert_eq!(resolve(&mut skel, &packet(9, &[0; 8])), BAD_KEY);
}
