use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TC_EGRESS, TC_INGRESS};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::xdp_manager::NativeXdpLink;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject, TcHookProxy};
use crate::runtime::EbpfRuntime;

pub(crate) mod xdp_wan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

mod tc_wan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_intro.skel.rs"));
}

mod tc_wan_egress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_intro.skel.rs"));
}

use tc_wan_egress_intro_skel::TcWanEgressIntroSkelBuilder;
use tc_wan_ingress_intro_skel::TcWanIngressIntroSkelBuilder;
use xdp_wan_route_skel::XdpWanRouteSkelBuilder;

pub struct XdpWanRouteHandle {
    _link: NativeXdpLink,
    _skel: xdp_wan_route_skel::XdpWanRouteSkel<'static>,
    _backing: OwnedOpenObject,
    _intro_skel: tc_wan_ingress_intro_skel::TcWanIngressIntroSkel<'static>,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    _egress_intro_skel: tc_wan_egress_intro_skel::TcWanEgressIntroSkel<'static>,
    _egress_intro_backing: OwnedOpenObject,
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
    has_mac: bool,
) -> LdEbpfResult<XdpWanRouteHandle> {
    let paths = &rt.paths;
    let l3_offset: u32 = if has_mac { 14 } else { 0 };

    // ── XDP wan route ──

    let builder = XdpWanRouteSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_route skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        ),
        "xdp_wan_route pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path(),),
        "xdp_wan_route pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path(),),
        "xdp_wan_route pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_wan_route pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
        "xdp_wan_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "xdp_wan_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "xdp_wan_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "xdp_wan_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_target_slot_map, &paths.rt4_target_slot_map,),
        "xdp_wan_route pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_target_slot_map, &paths.rt6_target_slot_map,),
        "xdp_wan_route pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "xdp_wan_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "xdp_wan_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "xdp_wan_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "xdp_wan_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "xdp_wan_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "xdp_wan_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "xdp_wan_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "xdp_wan_route pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
        "xdp_wan_route pin xdp_redirect_able"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_route skeleton")?;

    rt.xdp.ensure_roots(ifindex)?;
    let link = NativeXdpLink::attach(rt.clone(), rt.xdp.wan_intro_prog(), ifindex)?;
    let exit_fd = skel.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();
    rt.xdp.set_exit(ifindex, exit_fd)?;

    // ── TC ingress intro (XDP handoff + normal TC processing) ──

    rt.tc.ensure_roots(ifindex, has_mac)?;

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
        TcHookProxy::new(&intro_skel.progs.tc_wan_intro, ifindex as i32, TC_INGRESS, 1);
    ingress_hook.attach();

    // ── TC egress intro (local outbound traffic) ──

    let builder = TcWanEgressIntroSkelBuilder::default();
    let (egress_intro_backing, egress_intro_obj) = OwnedOpenObject::new();
    let mut egress_intro_open_skel =
        bpf_ctx!(builder.open(egress_intro_obj), "open tc_wan_egress_intro")?;

    egress_intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

    crate::maps::reuse_pinned_map_or_recreate(
        &mut egress_intro_open_skel.maps.tc_wan_egress_roots,
        &paths.tc_wan_egress_roots_path(),
    );

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.flow_match_map, &paths.flow_match_map),
        "tc_wan_egress_intro pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "tc_wan_egress_intro pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "tc_wan_egress_intro pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "tc_wan_egress_intro pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut egress_intro_open_skel.maps.rt4_target_slot_map,
            &paths.rt4_target_slot_map,
        ),
        "tc_wan_egress_intro pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut egress_intro_open_skel.maps.rt6_target_slot_map,
            &paths.rt6_target_slot_map,
        ),
        "tc_wan_egress_intro pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "tc_wan_egress_intro pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "tc_wan_egress_intro pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "tc_wan_egress_intro pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "tc_wan_egress_intro pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "tc_wan_egress_intro pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "tc_wan_egress_intro pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "tc_wan_egress_intro pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut egress_intro_open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "tc_wan_egress_intro pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut egress_intro_open_skel.maps.xdp_redirect_able,
            &paths.xdp_redirect_able,
        ),
        "tc_wan_egress_intro pin xdp_redirect_able"
    )?;

    let egress_intro_skel = bpf_ctx!(egress_intro_open_skel.load(), "load tc_wan_egress_intro")?;

    let mut egress_hook = TcHookProxy::new(
        &egress_intro_skel.progs.tc_wan_egress_intro,
        ifindex as i32,
        TC_EGRESS,
        1,
    );
    egress_hook.attach();

    Ok(XdpWanRouteHandle {
        _link: link,
        _skel: skel,
        _backing: backing,
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        _egress_intro_skel: egress_intro_skel,
        _egress_intro_backing: egress_intro_backing,
        egress_hook: Some(egress_hook),
        _ifindex: ifindex,
    })
}
