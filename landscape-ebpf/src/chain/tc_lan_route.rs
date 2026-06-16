use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::TcChainManager;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject, TcHookProxy};
use crate::MAP_PATHS;

mod tc_lan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
}
use tc_lan_ingress_intro_skel::{TcLanIngressIntroSkel, TcLanIngressIntroSkelBuilder};

pub struct TcLanRouteHandle {
    _intro_skel: TcLanIngressIntroSkel<'static>,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    _ifindex: u32,
}

unsafe impl Send for TcLanRouteHandle {}
unsafe impl Sync for TcLanRouteHandle {}

impl Drop for TcLanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
    }
}

pub fn init_tc_lan_route(
    ifindex: u32,
    has_mac: bool,
    xdp_handoff_enabled: bool,
) -> LdEbpfResult<TcLanRouteHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex, has_mac)?;

    let l3_offset: u32 = if has_mac { 14 } else { 0 };

    let (intro_backing, obj) = OwnedOpenObject::new();
    let builder = TcLanIngressIntroSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open per-if tc_lan_ingress_intro")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = xdp_handoff_enabled;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
        "tc_lan_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "tc_lan_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
        "tc_lan_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
        "tc_lan_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_target_slot_map, &MAP_PATHS.rt4_target_slot_map),
        "tc_lan_route pin rt4_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_target_slot_map, &MAP_PATHS.rt6_target_slot_map),
        "tc_lan_route pin rt6_target_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
        "tc_lan_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
        "tc_lan_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
        "tc_lan_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
        "tc_lan_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
        "tc_lan_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
        "tc_lan_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "tc_lan_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "tc_lan_route pin ip_mac_v6"
    )?;
    let intro_skel = bpf_ctx!(open_skel.load(), "load per-if tc_lan_ingress_intro")?;
    let mut ingress_hook = TcHookProxy::new(
        &intro_skel.progs.tc_lan_ingress_intro,
        ifindex as i32,
        libbpf_rs::TC_INGRESS,
        1,
    );
    ingress_hook.attach();

    Ok(TcLanRouteHandle {
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        _ifindex: ifindex,
    })
}
