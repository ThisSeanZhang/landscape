use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::TC_INGRESS;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::TcChainManager;
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

mod tc_lan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
}
use tc_lan_ingress_intro_skel::TcLanIngressIntroSkelBuilder;

pub struct XdpLanRouteHandle {
    _link: NativeXdpLink,
    _skel: xdp_lan_route_skel::XdpLanRouteSkel<'static>,
    _backing: OwnedOpenObject,
    _intro_skel: tc_lan_ingress_intro_skel::TcLanIngressIntroSkel<'static>,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    ifindex: u32,
}

unsafe impl Send for XdpLanRouteHandle {}
unsafe impl Sync for XdpLanRouteHandle {}

impl Drop for XdpLanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        TcChainManager::instance().remove_roots(self.ifindex);
    }
}

pub fn init_xdp_lan_route(ifindex: u32, has_mac: bool) -> LdEbpfResult<XdpLanRouteHandle> {
    let l3_offset: u32 = if has_mac { 14 } else { 0 };

    // ── XDP lan route ──

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

    // ── TC ingress intro (XDP handoff + normal TC processing) ──

    TcChainManager::instance().ensure_roots(ifindex, has_mac)?;

    let (intro_backing, intro_obj) = OwnedOpenObject::new();
    let intro_builder = TcLanIngressIntroSkelBuilder::default();
    let mut intro_open_skel = bpf_ctx!(intro_builder.open(intro_obj), "open tc_lan_ingress_intro")?;

    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = true;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
        "tc_lan_ingress_intro pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "tc_lan_ingress_intro pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
        "tc_lan_ingress_intro pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
        "tc_lan_ingress_intro pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut intro_open_skel.maps.rt4_target_slot_map,
            &MAP_PATHS.rt4_target_slot_map,
        ),
        "tc_lan_ingress_intro pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut intro_open_skel.maps.rt6_target_slot_map,
            &MAP_PATHS.rt6_target_slot_map,
        ),
        "tc_lan_ingress_intro pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
        "tc_lan_ingress_intro pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
        "tc_lan_ingress_intro pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
        "tc_lan_ingress_intro pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
        "tc_lan_ingress_intro pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
        "tc_lan_ingress_intro pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
        "tc_lan_ingress_intro pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "tc_lan_ingress_intro pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "tc_lan_ingress_intro pin ip_mac_v6"
    )?;

    let intro_skel = bpf_ctx!(intro_open_skel.load(), "load tc_lan_ingress_intro")?;

    let mut ingress_hook =
        TcHookProxy::new(&intro_skel.progs.tc_lan_ingress_intro, ifindex as i32, TC_INGRESS, 1);
    ingress_hook.attach();

    Ok(XdpLanRouteHandle {
        _link: link,
        _skel: skel,
        _backing: backing,
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        ifindex,
    })
}
