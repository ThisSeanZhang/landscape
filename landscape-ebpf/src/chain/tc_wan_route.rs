use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::TC_EGRESS;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::{
    tc_pipe_root_progs_path, tc_wan_egress_roots_path, wan_intro_dispatch_path, TcChainManager,
};
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject, TcHookProxy};
use crate::MAP_PATHS;

mod tc_wan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_intro.skel.rs"));
}
use tc_wan_ingress_intro_skel::{TcWanIngressIntroSkel, TcWanIngressIntroSkelBuilder};

mod tc_wan_egress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_intro.skel.rs"));
}
use tc_wan_egress_intro_skel::{TcWanEgressIntroSkel, TcWanEgressIntroSkelBuilder};

pub struct TcWanRouteHandle {
    _intro_skel: TcWanIngressIntroSkel<'static>,
    _intro_backing: OwnedOpenObject,
    _egress_intro_skel: TcWanEgressIntroSkel<'static>,
    _egress_intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    egress_hook: Option<TcHookProxy>,
    ifindex: u32,
}

unsafe impl Send for TcWanRouteHandle {}
unsafe impl Sync for TcWanRouteHandle {}

impl Drop for TcWanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        self.egress_hook.take();
        TcChainManager::instance().remove_roots(self.ifindex);
    }
}

pub fn init_tc_wan_route(ifindex: u32, has_mac: bool) -> LdEbpfResult<TcWanRouteHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex, has_mac)?;

    let l3_offset: u32 = if has_mac { 14 } else { 0 };

    let (intro_backing, obj) = OwnedOpenObject::new();
    let builder = TcWanIngressIntroSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open per-if tc_wan_ingress_intro")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    crate::map_setting::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_pipe_root_progs,
        &tc_pipe_root_progs_path(),
    );
    crate::map_setting::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.wan_intro_dispatch_map,
        &wan_intro_dispatch_path(),
    );
    let intro_skel = bpf_ctx!(open_skel.load(), "load per-if tc_wan_ingress_intro")?;
    let mut ingress_hook =
        TcHookProxy::new(&intro_skel.progs.tc_wan_intro, ifindex as i32, libbpf_rs::TC_INGRESS, 1);
    ingress_hook.attach();

    let (egress_intro_backing, egress_obj) = OwnedOpenObject::new();
    let builder = TcWanEgressIntroSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(egress_obj), "open per-if tc_wan_egress_intro")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    crate::map_setting::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_wan_egress_roots,
        &tc_wan_egress_roots_path(),
    );
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
        "tc_wan_egress pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "tc_wan_egress pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
        "tc_wan_egress pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
        "tc_wan_egress pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_target_slot_map, &MAP_PATHS.rt4_target_slot_map),
        "tc_wan_egress pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_target_slot_map, &MAP_PATHS.rt6_target_slot_map),
        "tc_wan_egress pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
        "tc_wan_egress pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
        "tc_wan_egress pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
        "tc_wan_egress pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
        "tc_wan_egress pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
        "tc_wan_egress pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
        "tc_wan_egress pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "tc_wan_egress pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "tc_wan_egress pin ip_mac_v6"
    )?;
    let egress_intro_skel = bpf_ctx!(open_skel.load(), "load per-if tc_wan_egress_intro")?;
    let mut egress_hook = TcHookProxy::new(
        &egress_intro_skel.progs.tc_wan_egress_intro,
        ifindex as i32,
        TC_EGRESS,
        1,
    );
    egress_hook.attach();

    Ok(TcWanRouteHandle {
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        _egress_intro_skel: egress_intro_skel,
        _egress_intro_backing: egress_intro_backing,
        ingress_hook: Some(ingress_hook),
        egress_hook: Some(egress_hook),
        ifindex,
    })
}
