//! Differential test of the BPF-side `wan_trie` reader: Rust publishes the
//! entry set into the probe program's real arena through the mmap, then the
//! same case matrix as the pure-Rust builder tests is replayed through
//! `BPF_PROG_TEST_RUN` and compared against `reference_lpm` — proving the C
//! `wan_trie_resolve` walk and the `wan_trie_key_v4/ppp` byte-order
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

use crate::maps::wan_trie::arena::mapped_table;
use crate::maps::wan_trie::builder::tests::{d, p};
use crate::maps::wan_trie::builder::{
    PrefixEntry, ppp_entry, reference_lpm, v4_entry, v6_entry, wan_trie_publish,
};
use crate::tests::test_wan_trie_probe_skel::{TestWanTrieProbeSkel, TestWanTrieProbeSkelBuilder};

const MODE_RAW: u8 = 0;
const MODE_V4: u8 = 1;
const MODE_PPP: u8 = 2;
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
    wan_trie_publish(
        mapped_table(&mut skel.maps.wan_trie_arena).expect("owned trie arena mapping"),
        entries,
    )
    .expect("publish");
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
        ppp_entry(1, 0x1234, 62),
    ];
    publish(&mut skel, &entries);

    // v6 prefix64 through the raw-key mode
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd22:2222:33ab::1"))), 60);
    assert_eq!(resolve(&mut skel, &packet(MODE_RAW, &d("fd99::1"))), 0);

    // v4 daddr: payload 203.0.113.7 in network order
    assert_eq!(resolve(&mut skel, &packet(MODE_V4, &[203, 0, 113, 7])), 61);
    assert_eq!(resolve(&mut skel, &packet(MODE_V4, &[203, 0, 114, 7])), 0);

    // ppp (ifindex, session): payload = ifindex then session, big-endian
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 1, 0x12, 0x34])), 62);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 1, 0x12, 0x35])), 0);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 2, 0x12, 0x34])), 0);

    // the same session id under two ifindexes resolves independently
    publish(&mut skel, &[ppp_entry(1, 0x1234, 62), ppp_entry(2, 0x1234, 63)]);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 1, 0x12, 0x34])), 62);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 2, 0x12, 0x34])), 63);
    assert_eq!(resolve(&mut skel, &packet(MODE_PPP, &[0, 0, 0, 3, 0x12, 0x34])), 0);

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

/// Exercise the production XDP seed's mmap, a reused TC intro and a reused
/// reader against both full halves. This catches base-address/layout mistakes
/// that loading alone cannot detect.
#[test]
fn shared_arena_full_capacity() {
    use crate::maps::wan_trie::types::{WAN_TRIE_POOL_NODES, WanTrieTbl};
    use crate::skel::tc_wan_ingress_intro::TcWanIngressIntroSkelBuilder;
    use crate::skel::xdp_wan_intro::XdpWanIntroSkelBuilder;
    use crate::tests::pkt::simple_ipv6_tcp_syn;
    use libbpf_rs::{MapCore, MapFlags};
    use std::os::fd::{AsFd, AsRawFd};

    const LEAVES: usize = 2039; // one root + eight branches + 2039 leaves
    fn key(i: usize) -> [u8; 8] {
        [0x20 + (i / 256) as u8, (i % 256) as u8, 255, 255, 255, 255, 255, 255]
    }
    let mut seed_obj = MaybeUninit::uninit();
    let mut seed = XdpWanIntroSkelBuilder::default().open(&mut seed_obj).unwrap().load().unwrap();
    let mut probe_obj = MaybeUninit::uninit();
    let mut open = TestWanTrieProbeSkelBuilder::default().open(&mut probe_obj).unwrap();
    open.maps.wan_trie_arena.reuse_fd(seed.maps.wan_trie_arena.as_fd()).unwrap();
    let mut probe = open.load().unwrap();
    assert!(
        mapped_table(&mut probe.maps.wan_trie_arena).is_err(),
        "reused map does not own an mmap"
    );
    let mut tc_obj = MaybeUninit::uninit();
    let mut open = TcWanIngressIntroSkelBuilder::default().open(&mut tc_obj).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = false;
    open.maps.wan_trie_arena.reuse_fd(seed.maps.wan_trie_arena.as_fd()).unwrap();
    let tc = open.load().unwrap();
    for (slot, xdp_fd, tc_fd) in [
        (
            5u32,
            probe.progs.test_xdp_sink_a.as_fd().as_raw_fd(),
            probe.progs.test_tc_sink_a.as_fd().as_raw_fd(),
        ),
        (
            6u32,
            probe.progs.test_xdp_sink_b.as_fd().as_raw_fd(),
            probe.progs.test_tc_sink_b.as_fd().as_raw_fd(),
        ),
    ] {
        seed.maps
            .xdp_pipe_root_progs
            .update(&slot.to_ne_bytes(), &xdp_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        tc.maps
            .tc_pipe_root_progs
            .update(&slot.to_ne_bytes(), &tc_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
    }
    let mut dst = [0u8; 16];
    dst[..8].copy_from_slice(&key(LEAVES - 1));
    dst[15] = 1;
    let frame = simple_ipv6_tcp_syn("fd00::1".parse().unwrap(), Ipv6Addr::from(dst));
    for generation in 1..=3u32 {
        let mut entries: Vec<_> = (0..LEAVES)
            .map(|i| PrefixEntry {
                prefix: key(i),
                plen: 16,
                root: generation * 10000 + i as u32 + 1,
            })
            .collect();
        {
            let tbl = mapped_table(&mut seed.maps.wan_trie_arena).unwrap();
            wan_trie_publish(tbl, &entries).unwrap();
            assert_eq!(tbl.cur, generation & 1);
            let h = &tbl.halves[tbl.cur as usize];
            assert_eq!(h.node_cnt as usize, WAN_TRIE_POOL_NODES);
            if tbl.cur == 1 {
                let end = &h.vals[1][31][31] as *const u32 as usize + 4;
                assert_eq!(end - tbl as *const WanTrieTbl as usize, size_of::<WanTrieTbl>());
            }
        }
        for j in 0..LEAVES {
            let i = (j * 997) % LEAVES;
            assert_eq!(resolve(&mut probe, &packet(MODE_RAW, &key(i))), entries[i].root);
        }
        // The final leaf is node 2047. Change the final table word to a real
        // chain slot and observe both production intros reaching its sink.
        let changed_byte = ((generation - 1) & 1) as usize;
        let slot = 5 + changed_byte as u32;
        {
            let tbl = mapped_table(&mut seed.maps.wan_trie_arena).unwrap();
            tbl.halves[tbl.cur as usize].vals[1][31][31] = slot;
        }
        assert_eq!(resolve(&mut probe, &packet(MODE_RAW, &key(LEAVES - 1))), slot);
        for (prog, retval) in [(&seed.progs.xdp_wan_intro, 2), (&tc.progs.tc_wan_ingress_intro, 0)]
        {
            let mut output = vec![0u8; frame.len() + 32];
            let result = prog
                .test_run(ProgramInput {
                    data_in: Some(&frame),
                    data_out: Some(&mut output),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(result.return_value, retval);
            let mut expected = frame.clone();
            expected[changed_byte] ^= 0xff;
            assert_eq!(result.data.unwrap(), expected);
        }
        entries.push(PrefixEntry { prefix: key(LEAVES), plen: 16, root: 7 });
        {
            let tbl = mapped_table(&mut seed.maps.wan_trie_arena).unwrap();
            let active = tbl.cur;
            assert!(wan_trie_publish(tbl, &entries).is_err());
            assert_eq!(tbl.cur, active);
        }
        assert_eq!(resolve(&mut probe, &packet(MODE_RAW, &key(LEAVES - 1))), slot);
    }
}
