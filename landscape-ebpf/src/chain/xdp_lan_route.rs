use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::xdp_manager::{
    xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
    xdp_pipe_root_progs_path, NativeXdpLink, XdpChainManager,
};
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject, TcHookProxy};
use crate::MAP_PATHS;

pub(crate) mod xdp_lan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_route.skel.rs"));
}

use xdp_lan_route_skel::XdpLanRouteSkelBuilder;

mod tc_docker_handoff_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_docker_handoff.skel.rs"));
}
use tc_docker_handoff_skel::{TcDockerHandoffSkel, TcDockerHandoffSkelBuilder};

pub struct XdpLanRouteHandle {
    _link: NativeXdpLink,
    _skel: xdp_lan_route_skel::XdpLanRouteSkel<'static>,
    _backing: OwnedOpenObject,
    _docker_skel: TcDockerHandoffSkel<'static>,
    _docker_backing: OwnedOpenObject,
    _docker_hook: TcHookProxy,
}

unsafe impl Send for XdpLanRouteHandle {}
unsafe impl Sync for XdpLanRouteHandle {}

pub fn init_xdp_lan_route(ifindex: u32) -> LdEbpfResult<XdpLanRouteHandle> {
    let builder = XdpLanRouteSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_route skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path(),),
        "xdp_lan_route pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path(),),
        "xdp_lan_route pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path(),),
        "xdp_lan_route pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_lan_route pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
        "xdp_lan_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "xdp_lan_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
        "xdp_lan_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
        "xdp_lan_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_target_slot_map, &MAP_PATHS.rt4_target_slot_map,),
        "xdp_lan_route pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_target_slot_map, &MAP_PATHS.rt6_target_slot_map,),
        "xdp_lan_route pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
        "xdp_lan_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
        "xdp_lan_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
        "xdp_lan_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
        "xdp_lan_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
        "xdp_lan_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
        "xdp_lan_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "xdp_lan_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "xdp_lan_route pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &MAP_PATHS.xdp_redirect_able),
        "xdp_lan_route pin xdp_redirect_able"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_route skeleton")?;

    let link = NativeXdpLink::attach(&skel.progs.xdp_lan_route, ifindex)?;

    XdpChainManager::instance().ensure_roots(ifindex)?;

    let (dh_backing, dh_obj) = OwnedOpenObject::new();
    let dh_builder = TcDockerHandoffSkelBuilder::default();
    let dh_open = bpf_ctx!(dh_builder.open(dh_obj), "open tc_docker_handoff skeleton")?;
    let dh_skel = bpf_ctx!(dh_open.load(), "load tc_docker_handoff skeleton")?;
    let mut docker_hook = TcHookProxy::new(
        &dh_skel.progs.tc_docker_handoff,
        ifindex as i32,
        libbpf_rs::TC_INGRESS,
        1,
    );
    docker_hook.attach();

    Ok(XdpLanRouteHandle {
        _link: link,
        _skel: skel,
        _backing: backing,
        _docker_skel: dh_skel,
        _docker_backing: dh_backing,
        _docker_hook: docker_hook,
    })
}
