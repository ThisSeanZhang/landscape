//! XDP -> TC cold vs warm WAN L2 handoff comparison (off-link Ethernet v4/v6).
//!
//! Conflicting gateway neighbour MAC (`NEIGH_MAC`, paired with `SLOT_MAC` in the
//! route slot) vs WAN egress root's confirmed gateway MAC (`CONFIRMED_MAC`, paired
//! with `WAN_MAC` in `egress_binding`).
//!
//! A pure TC IPv6 control uses the same veth rig without attaching XDP. It
//! compares the slot path with cache hits both before and after deleting the
//! ingress gateway neighbour, while the WAN root's confirmed MAC stays valid.
//!
//! The XDP handoff cases run at two levels:
//!
//! 1. **Live veth end-to-end (`#[ignore]`, run with `--include-ignored`)**:
//!    Runs the full production chain on real veth pairs with zero simulated
//!    metadata or `skb->cb`:
//!      `xdp_lan_route` (XDP_PASS + real `data_meta`)
//!      -> `tc_lan_ingress_route` (`xdp_handoff_enabled = true`, `ls_lan_ingress_tails`
//!         cleared so missing metadata cannot fall back to normal TC routing)
//!      -> `tc_wan_egress_route` (`ls_wan_e_tails` cleared so only `tc_cb_forwarded`
//!         + matching `CHAIN` can enter `tc_wan_egress_roots[CHAIN]`)
//!      -> `tc_wan_egress_root` (reuses `ip_mac_v4` with conflicting `NEIGH_MAC`,
//!         configured with `CONFIRMED_MAC` + `WAN_MAC`)
//!      -> raw `AF_PACKET` capture bound strictly to the WAN peer veth.
//!
//! 2. **Two-stage `BPF_PROG_TEST_RUN` (runs by default)**:
//!    - **Measured (Stage 1)**: real `xdp_lan_route` via `BPF_PROG_TEST_RUN` (with
//!      `reuse_route_neighbours`), asserting `XDP_PASS`, inspecting the real
//!      `xdp_handoff_meta` written via `bpf_xdp_adjust_meta`, and asserting both
//!      cold and warm handoffs preserve the original Ethernet frame.
//!    - **Simulated bridge**: Linux `bpf_prog_test_run_skb` does not populate
//!      `skb->data_meta`, so `tc_lan_ingress_route::xdp_handoff_check` cannot be
//!      driven with XDP metadata under `test_run`. We translate the real
//!      `xdp_handoff_meta` observed from Stage 1 into the exact `TestSkb` that
//!      `tc_cb_mark_forwarded` stamps (`cb[0] = 1`, `cb[1] = chain << 16`).
//!    - **Measured (Stage 2)**: real `tc_wan_egress_route` (`ls_wan_e_tails`
//!      cleared) -> tail call -> real `tc_wan_egress_root` (reusing `ip_mac_v4`),
//!      fed both real post-XDP frames from Stage 1, asserting both produce the
//!      same `(CONFIRMED_MAC, WAN_MAC)` Ethernet header.

use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::time::{Duration, Instant};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::l2_fixture::*;
use crate::LandscapeMapPath;
use crate::landscape::pin_and_reuse_map;
use crate::skel::tc_lan_ingress_route::TcLanIngressRouteSkelBuilder;
use crate::skel::tc_wan_egress_root::{TcWanEgressRootSkelBuilder, types::wan_egress_binding};
use crate::skel::tc_wan_egress_route::TcWanEgressRouteSkelBuilder;
use crate::skel::xdp_lan_route::XdpLanRouteSkelBuilder;
use crate::tests::TestSkb;
use crate::tests::helper::net::{NetNsGuard, TCAttach, VethPair, send_raw_packet};

const CHAIN: u16 = 9;
const XDP_PASS: u32 = 2;
const TC_ACT_UNSPEC: i32 = -1;
const XDP_HANDOFF_TC_REDIRECT_MAGIC: u32 = 0x4C44_5443;

/// `struct xdp_md` mirror for `BPF_PROG_TEST_RUN`.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, Default, Debug)]
struct HandoffXdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

/// Mirror of `struct xdp_handoff_meta` for `XDP_HANDOFF_TC_REDIRECT_MAGIC`
/// (`chain/xdp_meta.h`).
#[repr(C)]
#[derive(FromBytes, Immutable, Debug, Clone, Copy)]
struct XdpTcRedirectMeta {
    magic: u32,
    mark: u32,
    target_ifindex: u32,
    link_chain_id: u16,
    _pad: u16,
}

fn mac_word(mac: [u8; 6]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[..6].copy_from_slice(&mac);
    u64::from_ne_bytes(bytes)
}

fn egress_binding_for(wan_ifindex: u32) -> wan_egress_binding {
    wan_egress_binding {
        ifindex: wan_ifindex,
        has_l2: 1,
        is_pppoe: 0,
        has_ipv4: 1,
        has_ipv6: 1,
        wan_ip4: u32::from_ne_bytes(WAN4.octets()),
        wan_mask4: u32::from_ne_bytes([255, 255, 255, 0]),
        gateway_ip4: u32::from_ne_bytes(GW4.octets()),
        source_mac: WAN_MAC,
        ..Default::default()
    }
}

fn load_wan_egress_root<'obj>(
    pin_root: &Path,
    wan_ifindex: u32,
    obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
) -> crate::skel::tc_wan_egress_root::TcWanEgressRootSkel<'obj> {
    let paths = LandscapeMapPath::from_root(pin_root);
    let mut builder = TcWanEgressRootSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(pin_root).unwrap();
    let mut open = builder.open(obj).expect("open tc_wan_egress_root");
    // Reuse ip_mac_v4 so the conflicting NEIGH_MAC seeded by the fixture is
    // visible to the root and confirmed_gateway_mac must beat it.
    pin_and_reuse_map(&mut open.maps.ip_mac_v4, &paths.ip_mac_v4).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().egress_binding = egress_binding_for(wan_ifindex);
    let mut skel = open.load().expect("load tc_wan_egress_root");
    let bss = skel.maps.bss_data.as_deref_mut().unwrap();
    bss.confirmed_gateway_mac = mac_word(CONFIRMED_MAC);
    bss.confirmed_gateway_mac6 = mac_word(CONFIRMED_MAC);
    skel
}

fn load_wan_egress_route<'obj>(
    pin_root: &Path,
    root_fd: i32,
    obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
) -> crate::skel::tc_wan_egress_route::TcWanEgressRouteSkel<'obj> {
    let paths = LandscapeMapPath::from_root(pin_root);
    let mut builder = TcWanEgressRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(pin_root).unwrap();
    let mut open = builder.open(obj).expect("open tc_wan_egress_route");
    pin_and_reuse_map(&mut open.maps.ip_mac_v4, &paths.ip_mac_v4).unwrap();
    pin_and_reuse_map(&mut open.maps.ip_mac_v6, &paths.ip_mac_v6).unwrap();
    let skel = open.load().expect("load tc_wan_egress_route");

    // Clear all normal egress route workers so tc_wan_egress_route can ONLY
    // succeed via the `tc_cb_forwarded(skb)` -> `tc_wan_egress_roots[CHAIN]`
    // fast path.
    for slot in 0u32..4 {
        let _ = skel.maps.ls_wan_e_tails.delete(&slot.to_ne_bytes());
    }
    skel.maps
        .tc_wan_egress_roots
        .update(&u32::from(CHAIN).to_ne_bytes(), &(root_fd as u32).to_ne_bytes(), MapFlags::ANY)
        .expect("register tc_wan_egress_root in tc_wan_egress_roots");
    skel
}

fn open_wan_capture(ifindex: u32) -> socket2::Socket {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(i32::from((libc::ETH_P_ALL as u16).to_be()).into()),
    )
    .expect("create AF_PACKET capture socket");
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "bind AF_PACKET capture to ifindex {ifindex}: {}",
        std::io::Error::last_os_error()
    );
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock
}

fn recv_matching_frame(capture: &mut socket2::Socket, orig_frame: &[u8], label: &str) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match capture.read(&mut buf) {
            Ok(n) if n >= orig_frame.len() && buf[14..orig_frame.len()] == orig_frame[14..] => {
                return buf[..orig_frame.len()].to_vec();
            }
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => panic!("capture read failed for {label}: {e}"),
        }
    }
    panic!("timed out waiting for forwarded {label} frame on WAN peer");
}

fn assert_final_wan_l2(frame: &[u8], orig_frame: &[u8], label: &str) {
    assert_eq!(
        &frame[0..6],
        &CONFIRMED_MAC,
        "{label}: dst MAC must be confirmed gateway MAC (not conflicting NEIGH_MAC={NEIGH_MAC:02x?})"
    );
    assert_eq!(
        &frame[6..12],
        &WAN_MAC,
        "{label}: src MAC must be WAN root source MAC (not SLOT_MAC={SLOT_MAC:02x?})"
    );
    assert_eq!(&frame[12..], &orig_frame[12..], "{label}: L3/L4 payload must be preserved");
}

// ── 1. Live veth end-to-end production handoff ──

enum LanIngress {
    XdpHandoff(Family),
    TcV6,
    TcV6Tun,
}

enum LanDev {
    Veth(VethPair),
    Tun(std::fs::File, u32),
}

impl LanDev {
    fn ifindex(&self) -> u32 {
        match self {
            Self::Veth(pair) => pair.host_ifindex(),
            Self::Tun(_, ifindex) => *ifindex,
        }
    }

    fn inject(&mut self, peer_ns: &NetNsGuard, frame: &[u8]) {
        match self {
            Self::Veth(pair) => {
                let _peer = peer_ns.enter();
                send_raw_packet(pair.peer(), frame);
            }
            Self::Tun(tun, _) => {
                let raw_l3 = &frame[14..];
                assert_eq!(raw_l3[0] >> 4, 6, "TUN fixture payload must be bare IPv6");
                tun.write_all(raw_l3).expect("inject bare IPv6 packet into TUN");
            }
        }
    }
}

fn open_tun(name: &str) -> (std::fs::File, u32) {
    let tun = std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .expect("open /dev/net/tun");
    // SAFETY: ifreq is a plain C struct safe to zero-initialize.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: TUNSETIFF takes a writable ifreq for this open TUN fd.
    let rc = unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
    assert_eq!(rc, 0, "TUNSETIFF {name}: {}", std::io::Error::last_os_error());
    let up = std::process::Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .output()
        .expect("bring up TUN");
    assert!(up.status.success(), "ip link set {name} up: {}", String::from_utf8_lossy(&up.stderr));
    let ifindex = nix::net::if_::if_nametoindex(name).expect("TUN ifindex");
    (tun, ifindex)
}

fn run_live_veth(ingress: LanIngress) {
    let (family, tag, handoff, pure_l3) = match ingress {
        LanIngress::XdpHandoff(Family::V4) => (Family::V4, "v4", true, false),
        LanIngress::XdpHandoff(Family::V6) => (Family::V6, "v6", true, false),
        LanIngress::TcV6 => (Family::V6, "tcv6", false, false),
        LanIngress::TcV6Tun => (Family::V6, "l3v6", false, true),
    };
    let test_ns = NetNsGuard::create(&format!("l2h{tag}"));
    let peer_ns = NetNsGuard::create(&format!("l2p{tag}"));
    // TCAttach::drop also looks up the ifindex in the current netns. Keep the
    // router namespace and LAN device active for the full lifetime of both hooks.
    let _router_ns = test_ns.enter();
    let mut lan_dev = if pure_l3 {
        let (tun, ifindex) = open_tun(&format!("l3l{tag}"));
        LanDev::Tun(tun, ifindex)
    } else {
        LanDev::Veth(VethPair::create_with_netns(&format!("l2l{tag}"), &peer_ns))
    };
    let wan_pair = VethPair::create_with_netns(&format!("l2w{tag}"), &peer_ns);
    let lan_ifindex = lan_dev.ifindex();
    let wan_ifindex = wan_pair.host_ifindex();
    assert_ne!(lan_ifindex, wan_ifindex, "LAN and WAN ifindexes must differ");

    let pin_root = crate::tests::isolated_pin_root(&format!("l2-handoff-live-{tag}"));
    let paths = LandscapeMapPath::from_root(&pin_root);
    let case = seed_route(&pin_root, family, wan_ifindex, CHAIN);

    // Pure TC must run the real LAN family worker, with no XDP program attached.
    let _xdp_link = handoff.then(|| {
        let mut xobj = MaybeUninit::uninit();
        let mut xb = XdpLanRouteSkelBuilder::default();
        xb.object_builder_mut().pin_root_path(&pin_root).unwrap();
        let mut xopen = xb.open(&mut xobj).expect("open xdp_lan_route");
        reuse_route_neighbours(&mut xopen, &pin_root);
        pin_and_reuse_map(&mut xopen.maps.xdp_redirect_able, &paths.xdp_redirect_able).unwrap();
        let xskel = xopen.load().expect("load xdp_lan_route");
        xskel.progs.xdp_lan_route.attach_xdp(lan_ifindex as i32).unwrap()
    });

    let mut tobj = MaybeUninit::uninit();
    let mut tb = TcLanIngressRouteSkelBuilder::default();
    tb.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut topen = tb.open(&mut tobj).expect("open tc_lan_ingress_route");
    {
        let rodata = topen.maps.rodata_data.as_deref_mut().unwrap();
        rodata.xdp_handoff_enabled = handoff;
        if pure_l3 {
            rodata.current_l3_offset = 0;
        }
    }
    pin_and_reuse_map(&mut topen.maps.ip_mac_v4, &paths.ip_mac_v4).unwrap();
    pin_and_reuse_map(&mut topen.maps.ip_mac_v6, &paths.ip_mac_v6).unwrap();
    pin_and_reuse_map(&mut topen.maps.xdp_redirect_able, &paths.xdp_redirect_able).unwrap();
    let tskel = topen.load().expect("load tc_lan_ingress_route");
    if handoff {
        // With XDP attached, a missing handoff must not be masked by ordinary TC routing.
        for slot in 0u32..2 {
            tskel.maps.ls_lan_ingress_tails.delete(&slot.to_ne_bytes()).unwrap();
        }
    }

    // WAN egress root + route (strictly gated on tc_cb_forwarded + CHAIN).
    let mut root_obj = MaybeUninit::uninit();
    let root_skel = load_wan_egress_root(&pin_root, wan_ifindex, &mut root_obj);
    let root_fd = root_skel.progs.tc_wan_egress_root.as_fd().as_raw_fd();
    let mut route_obj = MaybeUninit::uninit();
    let route_skel = load_wan_egress_route(&pin_root, root_fd, &mut route_obj);

    let _tc_in = TCAttach::attach_ingress(&tskel.progs.tc_lan_ingress_route, lan_ifindex as i32);
    let _tc_out =
        TCAttach::attach_egress(&route_skel.progs.tc_wan_egress_route, wan_ifindex as i32);

    let mut capture = {
        let _e = peer_ns.enter();
        open_wan_capture(wan_pair.peer_ifindex())
    };

    let mut check_wire = |label: &str| {
        lan_dev.inject(&peer_ns, &case.packet);
        let wire = recv_matching_frame(&mut capture, &case.packet, label);
        if pure_l3 {
            assert_eq!(
                &wire[12..14],
                &[0x86, 0xdd],
                "{label}: rebuilt Ethernet header must carry IPv6 EtherType 0x86dd"
            );
        }
        assert_final_wan_l2(&wire, &case.packet, label);
        wire
    };
    assert_eq!(case.cached_ifindex(), None);
    let cold = check_wire("cold slot");
    assert_eq!(case.cached_ifindex(), Some(wan_ifindex));
    case.remove_slot(); // No slow-path fallback can pass either warm check.
    assert_eq!(check_wire("cached, conflicting gateway neighbour"), cold);
    if !handoff {
        // Both helpers return TC_ACT_REDIRECT under TEST_RUN. Without a kernel
        // route/neighbour for this gateway, only direct redirect reaches the WAN
        // root and delivers the data frame on the isolated peer.
        tskel.maps.ip_mac_v6.delete(&GW6.octets()).unwrap();
        assert_eq!(check_wire("cached, absent gateway neighbour"), cold);
    }
}

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_to_tc_cold_vs_warm_live_veth_v4() {
    run_live_veth(LanIngress::XdpHandoff(Family::V4));
}

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_to_tc_cold_vs_warm_live_veth_v6() {
    run_live_veth(LanIngress::XdpHandoff(Family::V6));
}

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tc_ipv6_lan_cache_leaves_l2_to_wan_root_live_veth() {
    run_live_veth(LanIngress::TcV6);
}

#[test]
#[ignore = "requires root, /dev/net/tun and network namespaces; run with --include-ignored"]
fn tc_ipv6_pure_l3_lan_to_eth_wan_cold_vs_warm_live_tun() {
    run_live_veth(LanIngress::TcV6Tun);
}

// ── 2. Two-stage BPF_PROG_TEST_RUN comparison (default non-ignored) ──

/// Pick an existing non-loopback interface in the current netns for
/// `BPF_PROG_TEST_RUN`'s `xdp_md.ingress_ifindex` so it differs from
/// `WAN_IFINDEX = 1` (host loopback, always valid for TC `test_run`).
fn find_non_lo_ifindex() -> u32 {
    let mut fallback = None;
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let Ok(raw) = std::fs::read_to_string(entry.path().join("ifindex")) else {
                continue;
            };
            let Ok(idx) = raw.trim().parse::<u32>() else {
                continue;
            };
            if idx == 3 {
                return idx;
            }
            if idx > 1 && fallback.is_none() {
                fallback = Some(idx);
            }
        }
    }
    fallback.unwrap_or(3)
}

fn run_xdp_stage(
    prog: &libbpf_rs::ProgramMut<'_>,
    pkt: &[u8],
    lan_ifindex: u32,
) -> (u32, XdpTcRedirectMeta, Vec<u8>) {
    let mut ctx_in = HandoffXdpMd {
        data: 0,
        data_end: pkt.len() as u32,
        data_meta: 0,
        ingress_ifindex: lan_ifindex,
        ..Default::default()
    };
    let mut ctx_out = HandoffXdpMd::default();
    let mut data_out = vec![0u8; pkt.len() + 64];
    let (ret, out) = {
        let res = prog
            .test_run(ProgramInput {
                data_in: Some(pkt),
                data_out: Some(&mut data_out),
                context_in: Some(ctx_in.as_mut_bytes()),
                context_out: Some(ctx_out.as_mut_bytes()),
                ..Default::default()
            })
            .expect("test_run xdp_lan_route");
        (res.return_value, res.data.expect("xdp data_out").to_vec())
    };
    let meta_len = ctx_out.data as usize;
    let end = ctx_out.data_end as usize;
    assert_eq!(
        meta_len,
        std::mem::size_of::<XdpTcRedirectMeta>(),
        "xdp_lan_route must prepend sizeof(struct xdp_handoff_meta) metadata bytes"
    );
    assert_eq!(end, out.len(), "xdp data_end must match output length");
    let meta = XdpTcRedirectMeta::read_from_bytes(&out[..meta_len])
        .expect("parse xdp_handoff_meta from XDP data_meta");
    let frame = out[meta_len..end].to_vec();
    (ret, meta, frame)
}

fn run_tc_egress_stage(
    prog: &libbpf_rs::ProgramMut<'_>,
    frame: &[u8],
    meta: XdpTcRedirectMeta,
) -> (i32, Vec<u8>, [u32; 5]) {
    // Simulated TC-intro handoff bridge: mirrors `tc_lan_ingress_route`'s
    // `xdp_handoff_check` (`skb->mark = meta.mark`, `tc_cb_mark_forwarded(skb,
    // meta.link_chain_id)`, `bpf_redirect(meta.target_ifindex, 0)`), because
    // `bpf_prog_test_run_skb` cannot carry `skb->data_meta`.
    let mut ctx_in = TestSkb {
        ifindex: meta.target_ifindex,
        mark: meta.mark,
        cb: [1, u32::from(meta.link_chain_id) << 16, 0, 0, 0],
        ..Default::default()
    };
    let mut ctx_out = TestSkb::default();
    let mut data_out = vec![0u8; frame.len()];
    let ret = prog
        .test_run(ProgramInput {
            data_in: Some(frame),
            data_out: Some(&mut data_out),
            context_in: Some(ctx_in.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("test_run tc_wan_egress_route")
        .return_value as i32;
    (ret, data_out, ctx_out.cb)
}

fn run_staged_test_run(family: Family) {
    const WAN_IFINDEX: u32 = 1; // host loopback: always valid for TC test_run egress
    let lan_ifindex = find_non_lo_ifindex();
    assert_ne!(lan_ifindex, WAN_IFINDEX, "XDP ingress ifindex must differ from WAN_IFINDEX");

    let tag = match family {
        Family::V4 => "v4",
        Family::V6 => "v6",
    };
    let pin_root = crate::tests::isolated_pin_root(&format!("l2-handoff-staged-{tag}"));
    let paths = LandscapeMapPath::from_root(&pin_root);
    let case = seed_route(&pin_root, family, WAN_IFINDEX, CHAIN);

    // Stage 1 (REAL): xdp_lan_route with reused neighbour maps so conflicting
    // NEIGH_MAC is visible on the warm LAN-cache hit.
    let mut xobj = MaybeUninit::uninit();
    let mut xb = XdpLanRouteSkelBuilder::default();
    xb.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut xopen = xb.open(&mut xobj).expect("open xdp_lan_route");
    reuse_route_neighbours(&mut xopen, &pin_root);
    pin_and_reuse_map(&mut xopen.maps.xdp_redirect_able, &paths.xdp_redirect_able).unwrap();
    let xskel = xopen.load().expect("load xdp_lan_route");

    // Packet 1 (COLD)
    let (cold_ret, cold_meta, cold_post_xdp) =
        run_xdp_stage(&xskel.progs.xdp_lan_route, &case.packet, lan_ifindex);
    assert_eq!(cold_ret, XDP_PASS, "{family:?} cold: xdp_lan_route must return XDP_PASS");
    assert_eq!(cold_meta.magic, XDP_HANDOFF_TC_REDIRECT_MAGIC);
    assert_eq!(cold_meta.target_ifindex, WAN_IFINDEX);
    assert_eq!(cold_meta.link_chain_id, CHAIN);
    assert_eq!(case.cached_ifindex(), Some(WAN_IFINDEX));
    assert_eq!(cold_post_xdp, case.packet, "cold TC handoff must keep the original frame");

    // Force Packet 2 to take the LAN-cache path.
    case.remove_slot();

    // Packet 2 (WARM)
    let (warm_ret, warm_meta, warm_post_xdp) =
        run_xdp_stage(&xskel.progs.xdp_lan_route, &case.packet, lan_ifindex);
    assert_eq!(warm_ret, XDP_PASS, "{family:?} warm: xdp_lan_route must return XDP_PASS via cache");
    assert_eq!(warm_meta.magic, XDP_HANDOFF_TC_REDIRECT_MAGIC);
    assert_eq!(warm_meta.target_ifindex, WAN_IFINDEX);
    assert_eq!(warm_meta.link_chain_id, CHAIN);
    assert_eq!(warm_post_xdp, case.packet, "cached TC handoff must leave L2 to WAN egress");

    // Stage 2 (REAL): tc_wan_egress_route -> tc_wan_egress_root (bridged from
    // Stage 1 via simulated TC-intro CB stamped from the real XDP meta).
    let mut root_obj = MaybeUninit::uninit();
    let root_skel = load_wan_egress_root(&pin_root, WAN_IFINDEX, &mut root_obj);
    let root_fd = root_skel.progs.tc_wan_egress_root.as_fd().as_raw_fd();
    let mut route_obj = MaybeUninit::uninit();
    let route_skel = load_wan_egress_route(&pin_root, root_fd, &mut route_obj);

    let (cold_tc_ret, cold_final, cold_cb) =
        run_tc_egress_stage(&route_skel.progs.tc_wan_egress_route, &cold_post_xdp, cold_meta);
    assert_eq!(cold_tc_ret, TC_ACT_UNSPEC, "{family:?} staged cold: root must run and exit");
    assert_eq!(cold_cb[2], 0, "{family:?} staged cold: must not fall back to neigh pending");
    assert_final_wan_l2(&cold_final, &case.packet, &format!("{family:?} staged cold"));

    let (warm_tc_ret, warm_final, warm_cb) =
        run_tc_egress_stage(&route_skel.progs.tc_wan_egress_route, &warm_post_xdp, warm_meta);
    assert_eq!(warm_tc_ret, TC_ACT_UNSPEC, "{family:?} staged warm: root must run and exit");
    assert_eq!(warm_cb[2], 0, "{family:?} staged warm: must not fall back to neigh pending");
    assert_final_wan_l2(&warm_final, &case.packet, &format!("{family:?} staged warm"));

    assert_eq!(warm_final, cold_final, "{family:?} staged: cold and warm final frames must match");
}

#[test]
fn xdp_to_tc_cold_vs_warm_staged_v4() {
    run_staged_test_run(Family::V4);
}

#[test]
fn xdp_to_tc_cold_vs_warm_staged_v6() {
    run_staged_test_run(Family::V6);
}
