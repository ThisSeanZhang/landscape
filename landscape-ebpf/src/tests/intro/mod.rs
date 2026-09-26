//! WAN ingress intro baseline tests.
//!
//! Locks the classification / dispatch behavior of the three WAN-side entry
//! programs before any further rewrite, using PROG_TEST_RUN only (no netns,
//! no real devices):
//!
//!   * `wan_intro_dispatch` (xdp_wan_intro.bpf.c) — native XDP: IP dispatch
//!     by daddr (v4) / /64 prefix (v6) with a v4-miss drop policy (WAN
//!     junk; v6 passes until v6 selector binding exists), PPPoE session
//!     dispatch with the lookup BEFORE the header strip (session miss
//!     passes the frame unmodified to pppd/kernel — no inner-IP fallback;
//!     bcast/mcast inner of a registered session is decapped for the local
//!     stack without chain metadata);
//!   * `tc_wan_intro` (tc_wan_ingress_intro.bpf.c) — TC ingress: IP dispatch
//!     only (never parses PPPoE; session selectors in the TC dispatch map are
//!     dead by design), supports raw-IP frames via current_l3_offset = 0
//!     (the virtual ppp device path); miss policy mirrors the XDP side:
//!     v4 unicast miss → TC_ACT_SHOT, bcast/mcast daddrs and v6 → stack;
//!   * `xdp_skb_pppoe` (xdp_skb_pppoe.bpf.c) — SKB-mode XDP stripper,
//!     dispatch-map driven: registered session → decap + PPP-chain handoff
//!     metadata (unicast) or decap without metadata for the local stack
//!     (bcast/mcast); everything else passes unmodified.
//!
//! All selectors are scoped by ingress ifindex (`struct dispatch_key` in
//! bpf/chain/wan_dispatch.h): two WAN links may reuse the same address or
//! PPPoE session id.
//!
//! PROG_TEST_RUN specifics (kernel net/bpf/test_run.c):
//!   * XDP ctx_in must keep data_meta = 0 and data_end == data_size_in;
//!     a non-zero ingress_ifindex requires an existing device WITH an XDP
//!     program attached (else -ENODEV / -EINVAL), so the XDP tests pass 0
//!     and the kernel substitutes its default loopback rxq — the effective
//!     ifindex is probed once via `xdp_effective_ifindex()` (0 or 1,
//!     kernel-dependent). The ifindex-scope *negative* assertions still
//!     hold: entries seeded for any other ifindex must never match.
//!   * XDP data_out covers [data_meta, data_end): a program that reserved
//!     metadata produces a meta-prefixed output.
//!   * TC ctx_in honors `ingress_ifindex` freely (no device lookup; only
//!     `ifindex` itself must be 0/1), and ctx_out writes `cb[]` back.
//!
//! The TC-side PPP-chain metadata fast path (tc_read_ppp_chain_handoff)
//! cannot be exercised under PROG_TEST_RUN — skb->data_meta of the run
//! context is kernel-controlled — so it is covered by the root-only
//! integration tests in `integration.rs`.

mod integration;
mod tc_wan_intro;
mod xdp_skb_pppoe;
mod xdp_wan_intro;

use std::sync::OnceLock;

use libbpf_rs::{MapCore, MapFlags};

use crate::landscape::OwnedOpenObject;
use crate::maps::wan::{dispatch_key, ppp_session_dispatch_key};

// enum xdp_action: ABORTED=0, DROP=1, PASS=2
pub(crate) const XDP_PASS: i32 = 2;
pub(crate) const XDP_DROP: i32 = 1;

pub(crate) const TC_ACT_OK: i32 = 0;
pub(crate) const TC_ACT_SHOT: i32 = 2;

/// XDP_HANDOFF_PPP_CHAIN_MAGIC ("LDPC"), stored native-endian by the C side.
pub(crate) const XDP_HANDOFF_PPP_CHAIN_MAGIC: u32 = 0x4C445043;
/// Size of `struct xdp_handoff_meta` (magic + 16-byte payload union… but the
/// union's largest member is 12 bytes; the struct is 16 with padding-free
/// alignment of u32 — magic(4) + payload(12)).
pub(crate) const HANDOFF_META_LEN: usize = 16;
/// Size of `struct xdp_pipe_meta` (mark + target_ifindex + chain_id).
pub(crate) const PIPE_META_LEN: usize = 12;

/// A fake ifindex guaranteed never to be the effective XDP test-run ifindex
/// (which is 0 or 1 — see `xdp_effective_ifindex`).
pub(crate) const WRONG_IFINDEX: u32 = 0x4242;

// ── selectors ──────────────────────────────────────────────────────────

pub(crate) fn seed_ip_selector(
    map: &impl MapCore,
    ifindex: u32,
    addr: std::net::IpAddr,
    chain_id: u32,
) {
    map.update(&dispatch_key(ifindex, addr), &chain_id.to_ne_bytes(), MapFlags::ANY).unwrap();
}

pub(crate) fn seed_ppp_session(map: &impl MapCore, ifindex: u32, session_id: u16, chain_id: u32) {
    map.update(
        &ppp_session_dispatch_key(ifindex, session_id),
        &chain_id.to_ne_bytes(),
        MapFlags::ANY,
    )
    .unwrap();
}

// ── frame builders ─────────────────────────────────────────────────────

pub(crate) const DMAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
pub(crate) const SMAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

const ETH_P_IPV4_BE: u16 = 0x0800;
const ETH_P_IPV6_BE: u16 = 0x86DD;
pub(crate) const PPP_PROTO_IPV4: u16 = 0x0021;
pub(crate) const PPP_PROTO_IPV6: u16 = 0x0057;
pub(crate) const PPP_PROTO_LCP: u16 = 0xC021;

/// [eth(14)][pppoe ver/code/sid/len(6)][ppp proto(2)][inner] — an
/// eth:PPPoE session frame (matches `struct pppoe_header` in the BPF side).
pub(crate) fn build_pppoe_frame(session_id: u16, ppp_proto: u16, inner: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + 8 + inner.len());
    f.extend_from_slice(&DMAC);
    f.extend_from_slice(&SMAC);
    f.extend_from_slice(&0x8864u16.to_be_bytes());
    f.push(0x11); // version(4) | type(4)
    f.push(0x00); // code: session data
    f.extend_from_slice(&session_id.to_be_bytes());
    f.extend_from_slice(&((inner.len() as u16) + 2).to_be_bytes());
    f.extend_from_slice(&ppp_proto.to_be_bytes());
    f.extend_from_slice(inner);
    f
}

/// eth:PPPoE discovery frame (0x8863), PADI-shaped.
pub(crate) fn build_pppoe_discovery_frame() -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + 8);
    f.extend_from_slice(&DMAC);
    f.extend_from_slice(&SMAC);
    f.extend_from_slice(&0x8863u16.to_be_bytes());
    f.extend_from_slice(&[0x11, 0x09]); // ver/type + PADI code
    f.extend_from_slice(&0x0000u16.to_be_bytes()); // session id 0
    f.extend_from_slice(&0x0004u16.to_be_bytes()); // payload length
    f.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // tag: service-name
    f
}

/// Plain eth frame with the given ethertype payload.
pub(crate) fn build_eth_frame(ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + l3.len());
    f.extend_from_slice(&DMAC);
    f.extend_from_slice(&SMAC);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(l3);
    f
}

/// IPv4 header (20B) + UDP header (8B), no ethernet.
pub(crate) fn build_raw_ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    p[1] = 0x00;
    let total_len = (p.len() as u16).to_be_bytes();
    p[4..6].copy_from_slice(&total_len);
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p
}

/// IPv6 header (40B) + UDP header (8B), no ethernet.
pub(crate) fn build_raw_ipv6(src: &[u8; 16], dst: &[u8; 16]) -> Vec<u8> {
    let mut p = vec![0u8; 40 + 8];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(8u16).to_be_bytes());
    p[6] = 17; // UDP
    p[7] = 64;
    p[8..24].copy_from_slice(src);
    p[24..40].copy_from_slice(dst);
    p
}

/// eth:IPv4 frame to `dst`.
pub(crate) fn build_ipv4_eth(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    build_eth_frame(ETH_P_IPV4_BE, &build_raw_ipv4(src, dst))
}

/// eth:IPv6 frame to `dst`.
pub(crate) fn build_ipv6_eth(src: &[u8; 16], dst: &[u8; 16]) -> Vec<u8> {
    build_eth_frame(ETH_P_IPV6_BE, &build_raw_ipv6(src, dst))
}

/// eth:ARP frame (zeros suffice — only the ethertype is classified).
pub(crate) fn build_arp_frame() -> Vec<u8> {
    let mut f = build_eth_frame(0x0806, &[0u8; 28]);
    f[14] = 0x00; // htype
    f[16] = 0x08; // ptype
    f
}

// ── XDP PROG_TEST_RUN ─────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct TestXdpMd {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

impl TestXdpMd {
    fn bytes(&self) -> [u8; std::mem::size_of::<TestXdpMd>()] {
        assert_eq!(std::mem::size_of::<TestXdpMd>(), 24, "must match struct xdp_md");
        unsafe { std::ptr::read((self as *const TestXdpMd).cast()) }
    }
}

/// Run an XDP program over `pkt` under PROG_TEST_RUN.
///
/// The context keeps data_meta = 0 / data_end = data_size_in (kernel
/// requirement) and ingress_ifindex = 0, so the kernel substitutes its
/// default loopback rxq — the program observes some fixed ifindex, see
/// `xdp_effective_ifindex`. The output buffer carries [data_meta, data_end),
/// so a program that reserved XDP metadata produces a meta-prefixed output.
pub(crate) fn xdp_run(prog: &libbpf_rs::ProgramMut, pkt: &[u8]) -> (i32, Vec<u8>) {
    let ctx = TestXdpMd {
        data: 0,
        data_end: pkt.len() as u32,
        data_meta: 0,
        ingress_ifindex: 0,
        rx_queue_index: 0,
        egress_ifindex: 0,
    };
    let mut ctx_bytes = ctx.bytes();
    let mut out = vec![0u8; pkt.len() + 64];
    let result = prog
        .test_run(libbpf_rs::ProgramInput {
            data_in: Some(pkt),
            data_out: Some(&mut out),
            context_in: Some(&mut ctx_bytes),
            ..Default::default()
        })
        .expect("xdp test_run");
    (result.return_value as i32, result.data.as_deref().map(|d| d.to_vec()).unwrap_or_default())
}

/// Interpret a PPPoE stripper output: the untouched frame (`out == pkt`),
/// [16B handoff meta][decapped frame] (`out.len() == pkt.len() - 8 + 16`), or
/// a decapped frame without metadata (`out.len() == pkt.len() - 8`, the
/// bcast/mcast-to-local-stack path).
pub(crate) fn ppp_stripper_out<'a>(out: &'a [u8], pkt: &[u8]) -> (Option<u32>, &'a [u8]) {
    match out.len() {
        n if n == pkt.len() => (None, out),
        n if n + 8 == pkt.len() + HANDOFF_META_LEN => {
            assert_eq!(
                out[0..4],
                XDP_HANDOFF_PPP_CHAIN_MAGIC.to_ne_bytes(),
                "reserved metadata must carry the PPP chain magic"
            );
            let chain_id = u32::from_ne_bytes(out[4..8].try_into().unwrap());
            (Some(chain_id), &out[HANDOFF_META_LEN..])
        }
        n if n + 8 == pkt.len() => (None, out),
        n => panic!("unexpected stripper output length {n} for input {}", pkt.len()),
    }
}

/// Interpret a WAN intro output: either the untouched frame or
/// [12B pipe meta][frame]. `stripped` is the number of bytes the intro
/// removed from the frame head before storing metadata (0 for the IP
/// dispatch paths, 8 for the PPPoE session path).
pub(crate) fn intro_pipe_out<'a>(
    out: &'a [u8],
    pkt: &[u8],
    stripped: usize,
) -> (Option<(u32, u32, u32)>, &'a [u8]) {
    match out.len() {
        n if n + stripped == pkt.len() => (None, out),
        n if n + stripped == pkt.len() + PIPE_META_LEN => {
            let mark = u32::from_ne_bytes(out[0..4].try_into().unwrap());
            let target = u32::from_ne_bytes(out[4..8].try_into().unwrap());
            let chain = u32::from_ne_bytes(out[8..12].try_into().unwrap());
            (Some((mark, target, chain)), &out[PIPE_META_LEN..])
        }
        n => panic!(
            "unexpected intro output length {n} for input {} (stripped {stripped})",
            pkt.len()
        ),
    }
}

/// The decapped frame the strippers must produce from `pkt`
/// (`build_pppoe_frame` layout): same MAC pair, ethertype from `l2_proto`,
/// then the inner payload verbatim.
pub(crate) fn expected_decapped(pkt: &[u8], l2_proto_be: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + pkt.len() - 22);
    f.extend_from_slice(&pkt[0..12]); // DMAC + SMAC preserved
    f.extend_from_slice(&l2_proto_be.to_be_bytes());
    f.extend_from_slice(&pkt[22..]); // inner packet (past eth+pppoe+proto)
    f
}

// ── skeleton guard ─────────────────────────────────────────────────────

/// A loaded skeleton plus its open-object backing.
///
/// The fields are ordered so the skeleton drops FIRST: libbpf objects live
/// inside the `OwnedOpenObject` backing, and a bare `let (skel, _obj)` would
/// drop the backing first (locals drop in reverse declaration order),
/// leaving the skeleton's Drop touching freed memory.
pub(crate) struct SkelGuard<S> {
    pub skel: S,
    _backing: OwnedOpenObject,
}

impl<S> std::ops::Deref for SkelGuard<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.skel
    }
}

// ── effective XDP ingress ifindex under test_run ───────────────────────

/// The ifindex an XDP program observes under PROG_TEST_RUN with
/// `ingress_ifindex = 0`: the kernel's default loopback rxq, i.e. 0 or 1
/// depending on kernel version. Probed once via the PPPoE stripper (a
/// registered session decaps only when the map key ifindex matches).
pub(crate) fn xdp_effective_ifindex() -> u32 {
    static CACHE: OnceLock<u32> = OnceLock::new();
    *CACHE.get_or_init(probe)
}

fn probe() -> u32 {
    use crate::bpf_rs_shared::xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder as _};

    let pin_root = crate::tests::isolated_pin_root("intro-ifindex-probe");
    let mut builder = XdpSkbPppoeSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut obj).unwrap().load().unwrap();

    let inner = build_raw_ipv4([203, 0, 113, 9], [198, 51, 100, 7]);
    let pkt = build_pppoe_frame(0x2101, PPP_PROTO_IPV4, &inner);

    for cand in [1u32, 0u32] {
        seed_ppp_session(&skel.maps.wan_intro_dispatch_map, cand, 0x2101, 9);
        let (ret, out) = xdp_run(&skel.progs.xdp_skb_pppoe, &pkt);
        let hit = ret == XDP_PASS
            && out.len() + 8 == pkt.len() + HANDOFF_META_LEN
            && out[0..4] == XDP_HANDOFF_PPP_CHAIN_MAGIC.to_ne_bytes();
        let _ = skel.maps.wan_intro_dispatch_map.delete(&ppp_session_dispatch_key(cand, 0x2101));
        if hit {
            return cand;
        }
    }
    panic!(
        "cannot determine the effective XDP ingress ifindex under PROG_TEST_RUN (tried 0 and 1)"
    );
}

// ── dispatch key layout lock ───────────────────────────────────────────
//
// Pins the 16-byte `struct dispatch_key` encoding shared between the C side
// (bpf/chain/wan_dispatch.h) and the Rust mirror (maps/wan/setting.rs).

#[test]
fn dispatch_key_v4_layout_is_stable() {
    let key = dispatch_key(0x11223344, "10.0.0.1".parse().unwrap());
    let mut expect = [0u8; 16];
    expect[0] = 0; // LANDSCAPE_IPV4_TYPE
    expect[4..8].copy_from_slice(&0x11223344u32.to_ne_bytes());
    expect[12..16].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(key, expect);
}

#[test]
fn dispatch_key_v6_layout_is_stable() {
    let addr: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let key = dispatch_key(7, std::net::IpAddr::V6(addr));
    let mut expect = [0u8; 16];
    expect[0] = 1; // LANDSCAPE_IPV6_TYPE
    expect[4..8].copy_from_slice(&7u32.to_ne_bytes());
    expect[8..16].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(key, expect);
}

#[test]
fn ppp_session_key_layout_is_stable() {
    // session id stored as a big-endian u16 at [14..16), verbatim from the
    // PPPoE header — no byte-order conversion on the C side.
    let key = ppp_session_dispatch_key(0x11223344, 0x2233);
    let mut expect = [0u8; 16];
    expect[0] = 3; // WAN_INTRO_PPP_SESSION_TYPE
    expect[4..8].copy_from_slice(&0x11223344u32.to_ne_bytes());
    expect[14..16].copy_from_slice(&[0x22, 0x33]);
    assert_eq!(key, expect);
}

#[test]
fn same_address_different_ifindex_yields_distinct_keys() {
    let a = dispatch_key(2, "203.0.113.7".parse().unwrap());
    let b = dispatch_key(3, "203.0.113.7".parse().unwrap());
    assert_ne!(a, b);
    assert_eq!(a[12..16], b[12..16]);
    assert_ne!(a[4..8], b[4..8]);
}

#[test]
fn same_session_id_different_ifindex_yields_distinct_keys() {
    let a = ppp_session_dispatch_key(2, 0x0001);
    let b = ppp_session_dispatch_key(3, 0x0001);
    assert_ne!(a, b);
}
