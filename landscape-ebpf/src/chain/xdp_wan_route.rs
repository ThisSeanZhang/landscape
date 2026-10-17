use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{TC_EGRESS, TC_INGRESS};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::runtime::EbpfRuntime;
use crate::xdp_attach::NativeXdpLink;

use crate::skel::tc_wan_egress_route::TcWanEgressRouteSkelBuilder;
use crate::skel::tc_wan_ingress_intro::TcWanIngressIntroSkelBuilder;

pub struct XdpWanRouteHandle {
    _link: NativeXdpLink,
    // TrieTarget: the guard field drops before the skeleton field, so the
    // trie target is detached while the arena mmap is still alive.
    _intro_trie: crate::maps::wan_trie::dispatcher::TrieTarget<
        crate::skel::tc_wan_ingress_intro::TcWanIngressIntroSkel<'static>,
    >,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    _egress_route_skel: crate::skel::tc_wan_egress_route::TcWanEgressRouteSkel<'static>,
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
    // The WAN route/exit program is loaded once as a backbone-lifetime
    // singleton (RouteBackbone::new) and pinned into the shared
    // `xdp_pipe_exits_wan` slot, so this handle only attaches the intro
    // dispatcher; the chain roots themselves are owned by the per-link
    // `WanLinkDataplane`, which loads them at construction.

    let link = rt.xdp_attach().attach_native(rt.backbone().wan_intro_prog(), ifindex)?;

    // ── TC ingress intro (XDP handoff + normal TC processing) ──

    let (intro_backing, intro_obj) = OwnedOpenObject::new();
    let intro_builder = TcWanIngressIntroSkelBuilder::default();
    let mut intro_open_skel = bpf_ctx!(intro_builder.open(intro_obj), "open tc_wan_ingress_intro")?;

    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = true;

    crate::maps::reuse_pinned_map_or_recreate(
        &mut intro_open_skel.maps.tc_pipe_root_progs,
        &paths.tc_pipe_root_progs_path(),
    );

    let intro_skel = bpf_ctx!(intro_open_skel.load(), "load tc_wan_ingress_intro")?;

    // Register the intro's dispatch-trie arena before attaching: the
    // dispatcher publishes the current entry set over the ELF-zeroed table.
    // A failure aborts the bring-up instead of attaching over a zeroed
    // table that would silently miss every dispatch.
    let intro_trie = crate::maps::wan_trie::dispatcher::TrieTarget::new(intro_skel, |s| {
        let data = s.maps.wan_trie_arena_data.as_mut().expect("wan_trie arena mmap data");
        rt.backbone().trie().register(cast_arena_tbl(&mut data.wan_trie_tbl))
    })?;

    let mut ingress_hook = TcHookProxy::new(
        &intro_trie.skel.progs.tc_wan_ingress_intro,
        ifindex as i32,
        TC_INGRESS,
        1,
    );
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
        _intro_trie: intro_trie,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        _egress_route_skel: egress_route_skel,
        _egress_route_backing: egress_route_backing,
        egress_hook: Some(egress_hook),
        _ifindex: ifindex,
    })
}
