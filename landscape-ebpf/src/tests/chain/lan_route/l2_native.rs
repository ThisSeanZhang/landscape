//! Native XDP LAN->WAN off-link L2 comparison: cold slot lookup vs warm LAN-cache hit.

use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput, ProgramMut,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::skel::xdp_lan_exit::XdpLanExitSkelBuilder;
use crate::skel::xdp_lan_root::{XdpLanRootSkelBuilder, types::wan_egress_binding};
use crate::skel::xdp_lan_route::XdpLanRouteSkelBuilder;

use super::XdpMd;
use super::l2_fixture::*;

const WAN_IFINDEX: u32 = 42;
const CHAIN: u16 = 9;
const XDP_REDIRECT: u32 = 4;
const META_SIZE: usize = std::mem::size_of::<XdpPipeMeta>();

/// Mirrors `struct xdp_pipe_meta` in `chain/xdp_meta.h`.
#[repr(C)]
#[derive(FromBytes, Immutable, Debug, PartialEq, Eq)]
struct XdpPipeMeta {
    mark: u32,
    target_ifindex: u32,
    target_chain_id: u32,
}

fn egress_binding_for(family: Family, ifindex: u32) -> wan_egress_binding {
    match family {
        Family::V4 => wan_egress_binding {
            ifindex,
            has_l2: 1,
            has_ipv4: 1,
            wan_ip4: u32::from_ne_bytes(WAN4.octets()),
            wan_mask4: u32::from_ne_bytes([255, 255, 255, 0]),
            gateway_ip4: u32::from_ne_bytes(GW4.octets()),
            source_mac: WAN_MAC,
            ..Default::default()
        },
        Family::V6 => wan_egress_binding {
            ifindex,
            has_l2: 1,
            has_ipv6: 1,
            wan_ip6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets(),
            wan_mask6: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0],
            gateway_ip6: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets(),
            source_mac: WAN_MAC,
            ..Default::default()
        },
    }
}

fn mac_to_u64(mac: [u8; 6]) -> u64 {
    let mut b = [0u8; 8];
    b[..6].copy_from_slice(&mac);
    u64::from_ne_bytes(b)
}

fn run_route(prog: &ProgramMut, pkt: &[u8]) -> (u32, XdpPipeMeta, Vec<u8>) {
    let mut ctx_in = XdpMd {
        data: 0,
        data_end: pkt.len() as u32,
        data_meta: 0,
        ingress_ifindex: 1,
        ..Default::default()
    };
    let mut ctx_out = XdpMd::default();
    let mut out_buf = vec![0u8; pkt.len() + 64];
    let (action, out) = {
        let res = prog
            .test_run(ProgramInput {
                data_in: Some(pkt),
                data_out: Some(&mut out_buf),
                context_in: Some(ctx_in.as_mut_bytes()),
                context_out: Some(ctx_out.as_mut_bytes()),
                ..Default::default()
            })
            .expect("test_run xdp_lan_route");
        (res.return_value, res.data.expect("data_out").to_vec())
    };
    let meta_len = (ctx_out.data - ctx_out.data_meta) as usize;
    assert!(meta_len >= META_SIZE, "meta_len {meta_len} < {META_SIZE}");
    assert_eq!(out.len(), (ctx_out.data_end - ctx_out.data_meta) as usize);
    let meta = XdpPipeMeta::read_from_bytes(&out[..META_SIZE]).unwrap();
    (action, meta, out[meta_len..].to_vec())
}

fn assert_cold_vs_warm(tag: &str, family: Family) {
    let pin = crate::tests::isolated_pin_root(tag);
    let case = seed_route(&pin, family, WAN_IFINDEX, CHAIN);

    let mut route_b = XdpLanRouteSkelBuilder::default();
    route_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut route_obj = MaybeUninit::uninit();
    let mut open = route_b.open(&mut route_obj).unwrap();
    reuse_route_neighbours(&mut open, &pin);
    let route = open.load().unwrap();
    route
        .maps
        .xdp_redirect_able
        .update(&WAN_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let mut exit_obj = MaybeUninit::uninit();
    let exit = XdpLanExitSkelBuilder::default().open(&mut exit_obj).unwrap().load().unwrap();
    let exit_fd = exit.progs.xdp_lan_exit.as_fd().as_raw_fd() as u32;

    let mut root_b = XdpLanRootSkelBuilder::default();
    root_b.object_builder_mut().pin_root_path(&pin).unwrap();
    let mut root_obj = MaybeUninit::uninit();
    let mut root_open = root_b.open(&mut root_obj).unwrap();
    {
        let ro = root_open.maps.rodata_data.as_deref_mut().unwrap();
        ro.current_chain = CHAIN as u32;
        ro.egress_binding = egress_binding_for(family, WAN_IFINDEX);
    }
    let mut root = root_open.load().unwrap();
    {
        let bss = root.maps.bss_data.as_deref_mut().unwrap();
        match family {
            Family::V4 => bss.confirmed_gateway_mac = mac_to_u64(CONFIRMED_MAC),
            Family::V6 => bss.confirmed_gateway_mac6 = mac_to_u64(CONFIRMED_MAC),
        }
    }
    root.maps
        .xdp_from_lan_exit_map
        .update(&0u32.to_ne_bytes(), &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    let root_fd = root.progs.xdp_lan_root.as_fd().as_raw_fd() as u32;
    let chain_key = (CHAIN as u32).to_ne_bytes();

    // Bypass the root with a non-rewriting exit to inspect the route stage's frame.
    route
        .maps
        .xdp_lan_pipe_root_progs
        .update(&chain_key, &exit_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    assert_eq!(case.cached_ifindex(), None);
    let (in_cold_act, in_cold_meta, in_cold_frame) =
        run_route(&route.progs.xdp_lan_route, &case.packet);
    assert_eq!((in_cold_act, in_cold_meta.target_ifindex), (XDP_REDIRECT, WAN_IFINDEX));
    assert_eq!(case.cached_ifindex(), Some(WAN_IFINDEX));
    let (in_warm_act, in_warm_meta, in_warm_frame) =
        run_route(&route.progs.xdp_lan_route, &case.packet);
    assert_eq!((in_warm_act, in_warm_meta.target_ifindex), (XDP_REDIRECT, WAN_IFINDEX));
    assert_eq!(in_cold_frame, case.packet, "cold route must leave the LAN frame intact");
    assert_eq!(in_warm_frame, case.packet, "LAN-cache hit must leave L2 to the WAN root");
    case.clear_cache();

    // Real route -> root -> exit: cold fills LAN cache, then slot removal forces warm cache hit.
    route
        .maps
        .xdp_lan_pipe_root_progs
        .update(&chain_key, &root_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    assert_eq!(case.cached_ifindex(), None);
    let cold = run_route(&route.progs.xdp_lan_route, &case.packet);
    assert_eq!(cold.0, XDP_REDIRECT);
    assert_eq!((cold.1.target_ifindex, cold.1.target_chain_id), (WAN_IFINDEX, CHAIN as u32));
    assert_eq!(&cold.2[..6], &CONFIRMED_MAC);
    assert_eq!(&cold.2[6..12], &WAN_MAC);
    assert_eq!(&cold.2[12..], &case.packet[12..]);
    assert_eq!(case.cached_ifindex(), Some(WAN_IFINDEX));

    case.remove_slot();
    let warm = run_route(&route.progs.xdp_lan_route, &case.packet);
    assert_eq!(warm, cold, "warm LAN-cache hit must match cold slot path after xdp_lan_root");
}

#[test]
fn xdp_lan_route_native_cold_vs_warm_l2_v4() {
    assert_cold_vs_warm("xdp-lr-l2-nat-v4", Family::V4);
}

#[test]
fn xdp_lan_route_native_cold_vs_warm_l2_v6() {
    assert_cold_vs_warm("xdp-lr-l2-nat-v6", Family::V6);
}
