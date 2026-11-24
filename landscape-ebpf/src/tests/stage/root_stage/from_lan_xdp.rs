use std::net::Ipv4Addr;

use libbpf_rs::ProgramInput;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

use crate::landscape::OwnedOpenObject;
use crate::tests::pkt::simple_ipv4_tcp;

use super::LAN_HOST;

const IFINDEX: u32 = 7;
const WAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);
const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 8);
const SRC: [u8; 6] = [2, 0, 0, 0, 0, 10];
const GW_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const XDP_PASS: u32 = 2;

const META_SIZE: usize = 12;

struct XdpLanRoot {
    skel: crate::skel::xdp_lan_root::XdpLanRootSkel<'static>,
    _backing: OwnedOpenObject,
}

fn load_root(binding: crate::skel::xdp_lan_root::types::wan_egress_binding) -> XdpLanRoot {
    let (backing, object) = OwnedOpenObject::new();
    let mut open =
        crate::skel::xdp_lan_root::XdpLanRootSkelBuilder::default().open(object).unwrap();
    let rodata = open.maps.rodata_data.as_deref_mut().unwrap();
    rodata.current_chain = 17;
    rodata.egress_binding = binding;
    XdpLanRoot { skel: open.load().unwrap(), _backing: backing }
}

fn binding() -> crate::skel::xdp_lan_root::types::wan_egress_binding {
    crate::skel::xdp_lan_root::types::wan_egress_binding {
        ifindex: IFINDEX,
        has_l2: 1,
        has_ipv4: 1,
        wan_ip4: u32::from_ne_bytes(WAN.octets()),
        wan_mask4: u32::from_ne_bytes([255, 255, 255, 0]),
        gateway_ip4: u32::from_ne_bytes(GATEWAY.octets()),
        source_mac: SRC,
        ..Default::default()
    }
}

fn set_confirmed(root: &mut XdpLanRoot, mac: &[u8; 6]) {
    let mut bytes = [0u8; 8];
    bytes[..6].copy_from_slice(mac);
    root.skel.maps.bss_data.as_deref_mut().unwrap().confirmed_gateway_mac =
        u64::from_ne_bytes(bytes);
}

/// `struct xdp_md` as accepted by BPF_PROG_TEST_RUN's `ctx_in`:
/// data/data_end/data_meta are offsets relative to data_meta; a zero meta
/// with data_end == packet length is the plain no-meta layout.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, Debug, Default)]
struct XdpMd {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

fn run_root(root: &XdpLanRoot, pkt: &[u8]) -> (u32, Vec<u8>) {
    let mut input = vec![0u8; META_SIZE + pkt.len()];
    input[4..8].copy_from_slice(&IFINDEX.to_ne_bytes());
    input[META_SIZE..].copy_from_slice(pkt);
    let mut ctx = XdpMd {
        data: META_SIZE as u32,
        data_end: input.len() as u32,
        data_meta: 0,
        ingress_ifindex: 1,
        ..Default::default()
    };
    let mut out = vec![0u8; input.len()];
    let ret = {
        let result = root
            .skel
            .progs
            .xdp_lan_root
            .test_run(ProgramInput {
                data_in: Some(&input),
                data_out: Some(&mut out),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("test_run xdp_lan_root");
        result.return_value
    };
    // test_run copies [data_meta, data_end]: the frame follows the meta.
    (ret, out[META_SIZE..].to_vec())
}

#[test]
fn off_link_uses_the_confirmed_gateway_mac() {
    let mut root = load_root(binding());
    set_confirmed(&mut root, &GW_MAC);
    let pkt = simple_ipv4_tcp(LAN_HOST, REMOTE);
    let (ret, out) = run_root(&root, &pkt);
    assert_eq!(ret, XDP_PASS, "all stage slots are empty in this rig");
    assert_eq!(&out[..6], &GW_MAC);
    assert_eq!(&out[6..12], &SRC);
    assert_eq!(out[12..], pkt[12..]);
}

#[test]
fn on_link_frames_keep_their_neighbour_header() {
    let mut root = load_root(binding());
    set_confirmed(&mut root, &GW_MAC);
    let pkt = simple_ipv4_tcp(LAN_HOST, PEER);
    let (_, out) = run_root(&root, &pkt);
    assert_eq!(out, pkt);
}

#[test]
fn unresolved_gateway_leaves_the_frame_untouched() {
    let root = load_root(binding());
    let pkt = simple_ipv4_tcp(LAN_HOST, REMOTE);
    let (_, out) = run_root(&root, &pkt);
    assert_eq!(out, pkt);
}

#[test]
fn directed_broadcast_and_prefix_edges_stay_untouched() {
    for (mask, dst, expect_untouched) in [
        // Directed broadcast of a /24 delegates to the kernel.
        ([255, 255, 255, 0], Ipv4Addr::new(192, 0, 2, 255), true),
        // A /31 has no broadcast address: both endpoints are hosts, so
        // anything off-link still takes the gateway.
        ([255, 255, 255, 254], Ipv4Addr::new(192, 0, 2, 255), false),
        // The other /31 endpoint is on-link.
        ([255, 255, 255, 254], PEER, true),
        // A /0 binding treats every destination as on-link.
        ([0; 4], REMOTE, true),
        // A /32 binding routes everything off-link.
        ([255; 4], GATEWAY, false),
    ] {
        let mut root = load_root(crate::skel::xdp_lan_root::types::wan_egress_binding {
            wan_mask4: u32::from_ne_bytes(mask),
            ..binding()
        });
        set_confirmed(&mut root, &GW_MAC);
        let pkt = simple_ipv4_tcp(LAN_HOST, dst);
        let (_, out) = run_root(&root, &pkt);
        if expect_untouched {
            assert_eq!(out, pkt, "mask={mask:?} dst={dst}");
        } else {
            assert_eq!(&out[..6], &GW_MAC, "mask={mask:?} dst={dst}");
            assert_eq!(&out[6..12], &SRC, "mask={mask:?} dst={dst}");
        }
    }
}

#[test]
fn non_ip_and_broadcast_frames_pass_through() {
    let mut root = load_root(binding());
    set_confirmed(&mut root, &GW_MAC);
    let mut bcast = simple_ipv4_tcp(LAN_HOST, REMOTE);
    bcast[0..6].copy_from_slice(&[0xff; 6]);
    bcast[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let (_, out) = run_root(&root, &bcast);
    assert_eq!(out, bcast);
}
