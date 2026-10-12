use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TC_EGRESS, TC_INGRESS};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::xdp_manager::NativeXdpLink;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::runtime::EbpfRuntime;

pub(crate) mod xdp_wan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

mod tc_wan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_intro.skel.rs"));
}

mod tc_wan_egress_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_route.skel.rs"));
}

use tc_wan_egress_route_skel::TcWanEgressRouteSkelBuilder;
use tc_wan_ingress_intro_skel::TcWanIngressIntroSkelBuilder;

pub struct XdpWanRouteHandle {
    _link: NativeXdpLink,
    _intro_skel: tc_wan_ingress_intro_skel::TcWanIngressIntroSkel<'static>,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    _egress_route_skel: tc_wan_egress_route_skel::TcWanEgressRouteSkel<'static>,
    _egress_route_backing: OwnedOpenObject,
    egress_hook: Option<TcHookProxy>,
    _ifindex: u32,
}

unsafe impl Send for XdpWanRouteHandle {}
unsafe impl Sync for XdpWanRouteHandle {}

impl Drop for XdpWanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        self.egress_hook.take();
    }
}

pub fn init_xdp_wan_route(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_eth_header: bool,
) -> LdEbpfResult<XdpWanRouteHandle> {
    let paths = &rt.paths;
    let l3_offset: u32 = if has_eth_header { 14 } else { 0 };

    // ── XDP wan route ──
    //
    // The WAN route/exit program is loaded once as a manager-lifetime
    // singleton (XdpChainManager::new) and pinned into the shared
    // `xdp_pipe_exits_wan` slot, so this handle only needs to bring up the
    // chains for this interface and attach the intro dispatcher.

    rt.xdp.ensure_roots(ifindex)?;
    let link = NativeXdpLink::attach(rt.clone(), rt.xdp.wan_intro_prog(), ifindex)?;

    // ── TC ingress intro (XDP handoff + normal TC processing) ──

    rt.tc.ensure_roots(ifindex, has_eth_header)?;

    let (intro_backing, intro_obj) = OwnedOpenObject::new();
    let intro_builder = TcWanIngressIntroSkelBuilder::default();
    let mut intro_open_skel = bpf_ctx!(intro_builder.open(intro_obj), "open tc_wan_ingress_intro")?;

    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = true;

    crate::maps::reuse_pinned_map_or_recreate(
        &mut intro_open_skel.maps.tc_pipe_root_progs,
        &paths.tc_pipe_root_progs_path(),
    );
    crate::maps::reuse_pinned_map_or_recreate(
        &mut intro_open_skel.maps.wan_intro_dispatch_map,
        &paths.tc_wan_intro_dispatch_path(),
    );

    let intro_skel = bpf_ctx!(intro_open_skel.load(), "load tc_wan_ingress_intro")?;

    let mut ingress_hook =
        TcHookProxy::new(&intro_skel.progs.tc_wan_ingress_intro, ifindex as i32, TC_INGRESS, 1);
    ingress_hook.attach();

    // ── TC egress route (local outbound traffic) ──

    let builder = TcWanEgressRouteSkelBuilder::default();
    let (egress_route_backing, egress_route_obj) = OwnedOpenObject::new();
    let mut egress_route_open_skel =
        bpf_ctx!(builder.open(egress_route_obj), "open tc_wan_egress_route")?;

    egress_route_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

    crate::maps::reuse_pinned_map_or_recreate(
        &mut egress_route_open_skel.maps.tc_wan_egress_roots,
        &paths.tc_wan_egress_roots_path(),
    );

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.flow_match_map, &paths.flow_match_map),
        "tc_wan_egress_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "tc_wan_egress_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "tc_wan_egress_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "tc_wan_egress_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt4_slot_map, &paths.rt4_slot_map,),
        "tc_wan_egress_route pin rt4_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt6_slot_map, &paths.rt6_slot_map,),
        "tc_wan_egress_route pin rt6_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "tc_wan_egress_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "tc_wan_egress_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "tc_wan_egress_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "tc_wan_egress_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "tc_wan_egress_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "tc_wan_egress_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "tc_wan_egress_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_route_open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "tc_wan_egress_route pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut egress_route_open_skel.maps.xdp_redirect_able,
            &paths.xdp_redirect_able,
        ),
        "tc_wan_egress_route pin xdp_redirect_able"
    )?;

    let egress_route_skel = bpf_ctx!(egress_route_open_skel.load(), "load tc_wan_egress_route")?;

    let mut egress_hook = TcHookProxy::new(
        &egress_route_skel.progs.tc_wan_egress_route,
        ifindex as i32,
        TC_EGRESS,
        1,
    );
    egress_hook.attach();

    Ok(XdpWanRouteHandle {
        _link: link,
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        _egress_route_skel: egress_route_skel,
        _egress_route_backing: egress_route_backing,
        egress_hook: Some(egress_hook),
        _ifindex: ifindex,
    })
}
