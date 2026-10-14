//! Control-plane builder for the `wan_trie` arena table.
//!
//! [`wan_trie_publish`] fills the spare half of a [`WanTrieTbl`] from a
//! plain entry list, then flips `cur` last, so readers never observe a
//! half-built table.
//!
//! Arbitrary prefix lengths are supported through prefix expansion: a
//! /plen = 8k + r (r > 0) prefix is stored as 2^(8-r) virtual byte-aligned
//! entries at depth k+1 (at most 128 copies), all children of the depth-k
//! node of the prefix. Virtual entries are applied in ascending plen order
//! (stable within one length), so a longer — or a later, on ties — entry
//! overwrites shorter/earlier ones at the same node: exact LPM nesting
//! semantics, with zero data-plane changes.

use zerocopy::IntoBytes;

use super::types::{WAN_TRIE_POOL_NODES, WanTrieHalf, WanTrieNode, WanTrieTbl};

/// One WAN prefix: `prefix` in network order (bits at or beyond `plen` are
/// ignored, the builder masks them off), `plen` 0..=64, `root` the dispatch
/// root. A `root` of 0 means "miss"; such entries are skipped.
///
/// Prefer the namespace constructors ([`v4_entry`], [`ppp_entry`],
/// [`v6_entry`]): a raw `PrefixEntry` can accidentally collide with the
/// tag namespaces (first key byte < 0x04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrefixEntry {
    pub prefix: [u8; 8],
    pub plen: u8,
    pub root: u32,
}

/// Namespace tag constants, mirroring `WAN_TRIE_TAG_*` in the header: the
/// first key byte of every non-IPv6 key. All live in IETF-reserved IPv6
/// space, so they never collide with a real v6 prefix.  (The 0x02 tag
/// once keyed a standalone ifindex namespace used as an ingress fallback;
/// it is retired — the PPP key itself now carries ifindex.)
pub(crate) const TAG_V4: u8 = 0x00;
pub(crate) const TAG_PPP: u8 = 0x03;

/// IPv4 entry: daddr at trie bytes 1..4 behind the tag; trie plen = 8 + plen
/// (so a v4 /24 sits at plen 32, exact /32 at plen 40). Mid-byte lengths
/// (/22 etc.) go through the normal expansion.
pub(crate) fn v4_entry(
    addr: std::net::Ipv4Addr,
    plen: u8,
    root: u32,
) -> Result<PrefixEntry, String> {
    if plen > 32 {
        return Err(format!("wan_trie: v4 plen {plen} exceeds 32"));
    }
    let o = addr.octets();
    Ok(PrefixEntry {
        prefix: [TAG_V4, o[0], o[1], o[2], o[3], 0, 0, 0],
        plen: 8 + plen,
        root,
    })
}

/// PPPoE session entry: `(ifindex, session)` at trie bytes 1..6 behind the
/// tag, both big-endian. Session ids are assigned per-NIC by the BRAS, so
/// the ingress ifindex namespaces them (the same session id on two NICs
/// never collides, and one NIC's sessions cluster under a shared prefix).
/// Exact match at plen 56 (7 hops).
pub(crate) fn ppp_entry(ifindex: u32, session: u16, root: u32) -> PrefixEntry {
    PrefixEntry {
        prefix: [
            TAG_PPP,
            (ifindex >> 24) as u8,
            (ifindex >> 16) as u8,
            (ifindex >> 8) as u8,
            ifindex as u8,
            (session >> 8) as u8,
            session as u8,
            0,
        ],
        plen: 56,
        root,
    }
}

/// IPv6 entry: the raw prefix64, plen 0..=64. The masked first byte must
/// stay out of the tag namespaces (>= 0x04), which every real prefix
/// satisfies: GUA 2000::/3, ULA fd00::/8, link-local fe80::/10, ...
pub(crate) fn v6_entry(
    addr: std::net::Ipv6Addr,
    plen: u8,
    root: u32,
) -> Result<PrefixEntry, String> {
    if plen > 64 {
        return Err(format!("wan_trie: v6 plen {plen} exceeds 64"));
    }
    let o = addr.octets();
    let masked_b0 =
        if plen == 0 { 0 } else { o[0] & (if plen >= 8 { 0xff } else { hi_mask(plen) }) };
    if masked_b0 < 0x04 {
        return Err(format!(
            "wan_trie: v6 prefix byte0 {masked_b0:#04x} falls in the tag namespaces (< 0x04)"
        ));
    }
    Ok(PrefixEntry { prefix: o[..8].try_into().unwrap(), plen, root })
}

/// High `r` bits of a byte, low `8 - r` bits zero.
fn hi_mask(r: u8) -> u8 {
    if r == 0 { 0 } else { !(0xff >> r) }
}

/// Prefix canonicalized to its plen: bits at or beyond `plen` zeroed.
pub(crate) fn masked_key(prefix: [u8; 8], plen: u8) -> [u8; 8] {
    let mut p = prefix;
    let k = (plen / 8) as usize;
    let r = plen % 8;
    if r > 0 {
        p[k + 1..].fill(0);
        p[k] &= hi_mask(r);
    } else {
        p[k..].fill(0);
    }
    p
}

/// Chunked node-pool indexing, mirroring the BPF side's flat `pool + idx`.
#[inline]
fn node_at(h: &WanTrieHalf, idx: usize) -> &WanTrieNode {
    &h.nodes[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

#[inline]
fn node_mut(h: &mut WanTrieHalf, idx: usize) -> &mut WanTrieNode {
    &mut h.nodes[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

/// Chunked parallel `vals` array indexing.
#[inline]
fn val_at(h: &WanTrieHalf, idx: usize) -> &u32 {
    &h.vals[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

#[inline]
fn val_mut(h: &mut WanTrieHalf, idx: usize) -> &mut u32 {
    &mut h.vals[(idx >> 10) & 1][(idx >> 5) & 31][idx & 31]
}

/// Publish `entries` into the spare half of `tbl` and flip `cur`.
///
/// Fails only if a plen exceeds 64 or the node pool is exhausted (each
/// non-byte-aligned entry may cost up to 129 nodes through expansion).
pub(crate) fn wan_trie_publish(
    tbl: &mut WanTrieTbl,
    entries: &[PrefixEntry],
) -> Result<(), String> {
    let spare = (tbl.cur ^ 1) as usize;
    let h = &mut tbl.halves[spare];
    // Zero the spare half (~2MB memset beats a 2048-node Default construction).
    h.as_mut_bytes().fill(0);

    // Expand to virtual byte-aligned entries...
    let mut virt: Vec<([u8; 8], u8, u8, u32)> = Vec::new(); // (prefix, plen, depth, root)
    for e in entries {
        if e.root == 0 {
            continue;
        }
        if e.plen > 64 {
            return Err(format!("wan_trie: plen {} exceeds 64", e.plen));
        }
        let k = e.plen / 8;
        let r = e.plen % 8;
        let mut p = e.prefix;
        if r > 0 {
            p[k as usize + 1..].fill(0);
            p[k as usize] &= hi_mask(r);
        } else {
            p[k as usize..].fill(0);
        }
        if r > 0 {
            let span = 1u16 << (8 - r);
            for x in 0..span {
                let mut vp = p;
                vp[k as usize] |= x as u8;
                virt.push((vp, e.plen, k + 1, e.root));
            }
        } else {
            virt.push((p, e.plen, k, e.root));
        }
    }
    // ...then apply in ascending plen order (stable): longer — or later, on
    // ties — entries overwrite shorter/earlier ones at shared nodes.
    virt.sort_by_key(|e| e.1);

    // Pass 1: structure + own values (child = index + 1, 0 = absent).
    let mut cnt: usize = 1; // node 0 = root
    for (p, _plen, depth, root) in &virt {
        let mut idx = 0usize;
        for &b in p.iter().take(*depth as usize) {
            let b = b as usize;
            let next = node_at(h, idx).child[b >> 5][b & 31] as usize;
            idx = if next == 0 {
                if cnt >= WAN_TRIE_POOL_NODES {
                    return Err(format!(
                        "wan_trie: node pool exhausted ({WAN_TRIE_POOL_NODES} nodes)"
                    ));
                }
                let new = cnt;
                cnt += 1;
                node_mut(h, idx).child[b >> 5][b & 31] = new as u32 + 1;
                new
            } else {
                next - 1
            };
        }
        *val_mut(h, idx) = *root;
    }

    // Pass 2: inherit values down. Parent indices are always smaller than
    // child indices (allocation order), so one ascending sweep is a valid
    // topological order; afterwards vals[idx] is already the LPM answer for
    // any dst reaching node idx.
    for idx in 0..cnt {
        let inherited = *val_at(h, idx);
        if inherited == 0 {
            continue;
        }
        let children: Vec<u32> =
            node_at(h, idx).child.iter().flatten().copied().filter(|c| *c != 0).collect();
        for c in children {
            let child_val = val_mut(h, (c - 1) as usize);
            if *child_val == 0 {
                *child_val = inherited;
            }
        }
    }

    h.node_cnt = cnt as u32;
    tbl.cur = spare as u32;
    Ok(())
}

/// Userspace mirror of the BPF `wan_trie_resolve` walk (for tests and
/// cross-checks). `dst` is the first 8 bytes of the destination address,
/// network order.
pub(crate) fn wan_trie_resolve(tbl: &WanTrieTbl, dst: &[u8; 8]) -> u32 {
    let h = &tbl.halves[(tbl.cur & 1) as usize];
    let mut idx = 0usize;
    for &b in dst {
        let b = b as usize;
        let c = node_at(h, idx).child[b >> 5][b & 31] as usize;
        if c == 0 {
            break;
        }
        idx = c - 1;
    }
    *val_at(h, idx)
}

/// Naive longest-prefix match, the semantic reference the trie is verified
/// against. Bits at or beyond `plen` are don't-care (masked, like the
/// builder), and ties (same prefix and plen) resolve to the later entry,
/// matching the builder's overwrite order.
pub(crate) fn reference_lpm(entries: &[PrefixEntry], dst: &[u8; 8]) -> u32 {
    let mut best_plen: i32 = -1;
    let mut best_root = 0;
    for e in entries {
        if e.root == 0 || e.plen > 64 {
            continue;
        }
        let k = (e.plen / 8) as usize;
        let r = e.plen % 8;
        let covers = e.prefix[..k] == dst[..k]
            && (r == 0 || (e.prefix[k] & hi_mask(r)) == (dst[k] & hi_mask(r)));
        if covers && e.plen as i32 >= best_plen {
            best_plen = e.plen as i32;
            best_root = e.root;
        }
    }
    best_root
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    /// `p("fd22:2222:33ab::/48", 3)`: entry from a human-readable prefix.
    /// Host bits beyond the plen are allowed; the builder masks them.
    pub(crate) fn p(addr: &str, root: u32) -> PrefixEntry {
        let (addr, plen) = addr.split_once('/').expect("prefix needs a /plen");
        PrefixEntry {
            prefix: Ipv6Addr::from_str(addr).unwrap().octets()[..8].try_into().unwrap(),
            plen: plen.parse().unwrap(),
            root,
        }
    }

    /// `d("fd22:2222:33ab:1234::1")`: the first 8 dst bytes; the host part
    /// may sit anywhere after them.
    pub(crate) fn d(addr: &str) -> [u8; 8] {
        Ipv6Addr::from_str(addr).unwrap().octets()[..8].try_into().unwrap()
    }

    /// Heap-allocate a zeroed table (4.2MB must not live on the test stack).
    pub(crate) fn tbl() -> Box<WanTrieTbl> {
        // SAFETY: every field is an integer array, so all-zero is valid.
        unsafe { Box::<WanTrieTbl>::new_zeroed().assume_init() }
    }

    /// Publish and return the table, for the table-level assertions.
    fn published(entries: &[PrefixEntry]) -> Box<WanTrieTbl> {
        let mut t = tbl();
        wan_trie_publish(&mut t, entries).expect("publish");
        t
    }

    /// Assert trie and reference agree on every (dst, expected) case.
    fn assert_cases(entries: &[PrefixEntry], tbl: &WanTrieTbl, cases: &[([u8; 8], u32)]) {
        for (dst, expect) in cases {
            assert_eq!(wan_trie_resolve(tbl, dst), *expect, "trie dst {dst:02x?}");
            assert_eq!(reference_lpm(entries, dst), *expect, "reference dst {dst:02x?}");
        }
    }

    /// Every prefix length 0..=64 must behave exactly like the reference
    /// LPM: the hit entry at that length, nested under fd22:2222:3300::/40,
    /// plus fd44:5555:3300::/40 as a same-length sibling distractor.
    #[test]
    fn exhaustive_plen_matches_reference() {
        let mut tbl = tbl();
        for plen in 0..=64u8 {
            let entries = [
                p(&format!("fd22:2222:33ab:1234::/{plen}"), 7),
                p("fd22:2222:3300::/40", 4),
                p("fd44:5555:3300::/40", 5),
            ];
            wan_trie_publish(&mut tbl, &entries).expect("publish");
            for dst in [
                d("fd22:2222:33ab:1234::1"),
                d("fd22:2222:33ab:1200::1"),
                d("fd22:2222:33ab:13ff::1"),
                d("fd99::1"),
            ] {
                assert_eq!(
                    wan_trie_resolve(&tbl, &dst),
                    reference_lpm(&entries, &dst),
                    "plen {plen}, dst {dst:02x?}"
                );
            }
        }
    }

    /// A tower of nested prefixes at mixed granularities (byte-aligned and
    /// mid-byte) resolves to the deepest covering entry from any depth.
    #[test]
    fn nesting_tower_resolves_deepest() {
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
        assert_cases(&entries, &published(&entries), &cases);
    }

    /// All sixteen mid-byte lengths /49../64 inserted into ONE table as a
    /// strictly nested ladder (each range contained in the previous), with
    /// root = plen so the expected winner is self-describing. Every dst is
    /// crafted to fall inside exactly its length's expansion range and
    /// outside the next-longer one.
    #[test]
    fn every_plen_49_to_64_nested_ladder() {
        let entries: Vec<PrefixEntry> = (49..=64)
            .map(|plen| p(&format!("fd22:2222:33ab:8000::/{plen}"), plen as u32))
            .collect();
        let tbl = published(&entries);

        let cases = [
            (d("fd22:2222:33ab:ffff::1"), 49), // b6 = 0xff in [0x80, 0xff]
            (d("fd22:2222:33ab:bfff::1"), 50), // b6 = 0xbf in [0x80, 0xbf]
            (d("fd22:2222:33ab:9fff::1"), 51), // b6 = 0x9f in [0x80, 0x9f]
            (d("fd22:2222:33ab:8fff::1"), 52), // b6 = 0x8f in [0x80, 0x8f]
            (d("fd22:2222:33ab:87ff::1"), 53), // b6 = 0x87 in [0x80, 0x87]
            (d("fd22:2222:33ab:83ff::1"), 54), // b6 = 0x83 in [0x80, 0x83]
            (d("fd22:2222:33ab:81ff::1"), 55), // b6 = 0x81 in [0x80, 0x81]
            (d("fd22:2222:33ab:80ff::1"), 56), // b6 = 0x80 exact, b7 = *
            (d("fd22:2222:33ab:807f::1"), 57), // b7 = 0x7f in [0x00, 0x7f]
            (d("fd22:2222:33ab:803f::1"), 58), // b7 = 0x3f in [0x00, 0x3f]
            (d("fd22:2222:33ab:801f::1"), 59), // b7 = 0x1f in [0x00, 0x1f]
            (d("fd22:2222:33ab:800f::1"), 60), // b7 = 0x0f in [0x00, 0x0f]
            (d("fd22:2222:33ab:8007::1"), 61), // b7 = 0x07 in [0x00, 0x07]
            (d("fd22:2222:33ab:8003::1"), 62), // b7 = 0x03 in [0x00, 0x03]
            (d("fd22:2222:33ab:8001::1"), 63), // b7 = 0x01 in [0x00, 0x01]
            (d("fd22:2222:33ab:8000::1"), 64), // exact /64
        ];
        assert_cases(&entries, &tbl, &cases);

        // 1 root + 6 path nodes + 128 depth-7 virtuals (/49) + 128 depth-8
        // virtuals (/57); the shorter expansions reuse the same nodes.
        assert_eq!(tbl.halves[tbl.cur as usize].node_cnt, 263);
    }

    /// A /49 expands to 128 depth-7 children: 1 root + 6 path nodes + 128.
    /// A byte-aligned /56 costs only the 7 path nodes + root.
    #[test]
    fn expansion_node_count() {
        let tbl = published(&[p("fd22:2222:33ab:8000::/49", 7)]);
        assert_eq!(tbl.halves[tbl.cur as usize].node_cnt, 135);

        let tbl = published(&[p("fd22:2222:33ab:1200::/56", 7)]);
        assert_eq!(tbl.halves[tbl.cur as usize].node_cnt, 8);
    }

    /// Duplicate prefixes resolve to the later entry; nesting wins over
    /// input order (the /64 beats the /56 listed after it).
    #[test]
    fn duplicates_and_order_independence() {
        let dup = [p("fd00:aa00::/32", 1), p("fd00:aa00::/32", 2)];
        let tbl = published(&dup);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd00:aa00::1")), 2);

        let nested = [p("fd00:aa00:0:55::/64", 6), p("fd00:aa00::/56", 5)];
        let tbl = published(&nested);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd00:aa00:0:55::1")), 6);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd00:aa00:0:66::1")), 5);
    }

    /// Republishing must fill the other half: entries from the previous
    /// generation disappear completely (the spare half is zeroed first).
    #[test]
    fn double_buffer_flip_drops_stale_entries() {
        let mut tbl = published(&[p("fd00::/16", 3)]);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd00:1122::1")), 3);

        wan_trie_publish(&mut tbl, &[p("fd44::/16", 4)]).expect("republish");
        assert_eq!(wan_trie_resolve(&tbl, &d("fd00:1122::1")), 0, "stale entry survived");
        assert_eq!(wan_trie_resolve(&tbl, &d("fd44::1")), 4);
    }

    /// A concrete WAN-style routing table: default + ULA + two ISP trees
    /// with byte-aligned and mid-byte lengths nested in one family, plus a
    /// sibling ISP branch and an unnormalized (dirty host bits) /60 entry.
    #[test]
    fn concrete_routing_table_matches_reference() {
        let entries = [
            p("::/0", 100),         // default route
            p("fd00::/8", 101),     // ULA
            p("fd22:2222::/32", 1), // ISP-A
            p("fd22:2222:3300::/40", 2),
            p("fd22:2222:33ab::/48", 3),
            p("fd22:2222:33ab:1200::/56", 5),  // site (b7 = *)
            p("fd22:2222:33ab:1280::/57", 6),  // b7 in [0x80, 0xff]
            p("fd22:2222:33ab:12e0::/59", 7),  // b7 in [0xe0, 0xff]
            p("fd22:2222:33ab:12e4::/64", 8),  // exact host
            p("fd22:2222:33ab:12ff::/60", 13), // dirty bits -> b7 in [0xf0, 0xff]
            p("fd44:5555::/32", 12),           // ISP-B
            p("fd44:5555:3399::/48", 9),
            p("fd44:5555:3399:aa00::/56", 10),
        ];
        let cases = [
            (d("fd22:2222:33ab:12e4::1"), 8), // exact /64
            (d("fd22:2222:33ab:12ef::1"), 7), // b7 in [0xe0, 0xef]
            (d("fd22:2222:33ab:12ea::1"), 7),
            (d("fd22:2222:33ab:12f5::1"), 13), // b7 in [0xf0, 0xff]: /60
            (d("fd22:2222:33ab:12df::1"), 6),  // b7 in [0x80, 0xdf]: /57
            (d("fd22:2222:33ab:1280::1"), 6),
            (d("fd22:2222:33ab:127f::1"), 5), // b7 < 0x80: /56
            (d("fd22:2222:33ab:1200::1"), 5),
            (d("fd22:2222:33ab:1300::1"), 3), // b6 != 0x12: /48
            (d("fd22:2222:33ff::1"), 2),      // b5 != 0xab: /40
            (d("fd22:2222:3400::1"), 1),      // b4 != 0x33: /32
            (d("fd22:2223::1"), 101),         // outside fd22:2222::/32: /8
            (d("fd00:1122::1"), 101),
            (d("fd44:5555:3399:aa01::1"), 10), // ISP-B /56
            (d("fd44:5555:3399:bb00::1"), 9),  // ISP-B /48
            (d("fd44:5555:3399::1"), 9),
            (d("fd44:5555:3300::1"), 12), // ISP-B /32
            (d("fd44:5556::1"), 101),     // outside fd44:5555::/32: /8
            (d("2001:db8::1"), 100),      // GUA: default route
        ];
        assert_cases(&entries, &published(&entries), &cases);
    }

    /// The namespace constructors must lay out keys exactly like the BPF
    /// `wan_trie_key_v4/ppp/ifx` helpers do (tag byte first, payload
    /// big-endian immediately behind it).
    #[test]
    fn tag_key_layout_matches_header() {
        assert_eq!(
            v4_entry(Ipv4Addr::new(203, 0, 113, 7), 32, 1).unwrap(),
            PrefixEntry {
                prefix: [0x00, 0xcb, 0x00, 0x71, 0x07, 0, 0, 0],
                plen: 40,
                root: 1
            }
        );
        // v4 /22 -> trie plen 30 (mid-byte, expansion covers 4 slots)
        assert_eq!(v4_entry(Ipv4Addr::new(10, 1, 2, 0), 22, 2).unwrap().plen, 30);

        assert_eq!(
            ppp_entry(9, 0x1234, 3),
            PrefixEntry {
                prefix: [0x03, 0, 0, 0, 9, 0x12, 0x34, 0],
                plen: 56,
                root: 3
            }
        );

        // v6 passes through with its real first byte.
        assert_eq!(
            v6_entry(Ipv6Addr::from_str("fd00::").unwrap(), 8, 5).unwrap(),
            PrefixEntry {
                prefix: [0xfd, 0, 0, 0, 0, 0, 0, 0],
                plen: 8,
                root: 5
            }
        );
    }

    /// One table, three namespaces, zero crosstalk: every tagged key and the
    /// v6 prefix resolve to their own root, and namespace misses fall to 0.
    #[test]
    fn namespaces_coexist_without_crosstalk() {
        let entries = [
            v6_entry(Ipv6Addr::from_str("fd22:2222:33ab::").unwrap(), 48, 60).unwrap(),
            v4_entry(Ipv4Addr::new(203, 0, 113, 0), 24, 61).unwrap(), // 203.0.113.0/24
            ppp_entry(7, 0x1234, 62),
        ];
        let tbl = published(&entries);

        // Mirrors of the BPF key helpers: the u64 register resolve walks,
        // packet byte j at bits 8j (walk order = little-endian extraction).
        let key = |mut k: u64| {
            let mut b = [0u8; 8];
            for slot in b.iter_mut() {
                *slot = (k & 0xff) as u8;
                k >>= 8;
            }
            b
        };
        let kv4 = (TAG_V4 as u64) | (u32::from_le_bytes([203, 0, 113, 7]) as u64) << 8;
        // wan_trie_key_ppp(7, 0x1234): tag | htonl(7) << 8 | session << 40
        let kppp =
            (TAG_PPP as u64) | (7u64 << 32) | (u16::from_le_bytes([0x12, 0x34]) as u64) << 40;
        // The retired 0x02 tag namespace must not resolve anything.
        let kifx = 0x02u64 | (7u32.swap_bytes() as u64) << 8;

        // The BPF key math must land exactly on the entry prefixes.
        assert_eq!(key(kv4), v4_entry(Ipv4Addr::new(203, 0, 113, 7), 32, 0).unwrap().prefix);
        assert_eq!(key(kppp), entries[2].prefix);

        assert_eq!(wan_trie_resolve(&tbl, &key(kv4)), 61);
        assert_eq!(wan_trie_resolve(&tbl, &key(kv4 ^ (1 << 24))), 0); // outside /24
        assert_eq!(wan_trie_resolve(&tbl, &key(kppp)), 62);
        assert_eq!(wan_trie_resolve(&tbl, &key(kppp + 1)), 0);
        assert_eq!(wan_trie_resolve(&tbl, &key(kifx)), 0);
        assert_eq!(wan_trie_resolve(&tbl, &key(kifx + 1)), 0);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd22:2222:33ab::1")), 60);
        assert_eq!(wan_trie_resolve(&tbl, &d("fd99::1")), 0);
    }

    /// v6 prefixes whose masked first byte falls into the tag region are
    /// rejected; real prefixes (GUA, ULA, link-local, short-but-high) pass.
    #[test]
    fn v6_tag_region_is_rejected() {
        for (addr, plen) in [
            ("::", 0),
            ("::", 8),
            ("0100::", 16),
            ("0200::", 7),
            ("0300::", 8),
            ("::", 3),
            ("0000::", 5),
        ] {
            assert!(
                v6_entry(Ipv6Addr::from_str(addr).unwrap(), plen, 1).is_err(),
                "{addr}/{plen} should be rejected"
            );
        }
        for (addr, plen) in [
            ("2000::", 3),
            ("fd00::", 8),
            ("fe80::", 10),
            ("2400::", 12),
            ("4000::", 2),
            ("8000::", 1),
        ] {
            assert!(
                v6_entry(Ipv6Addr::from_str(addr).unwrap(), plen, 1).is_ok(),
                "{addr}/{plen} should be accepted"
            );
        }
    }
}
