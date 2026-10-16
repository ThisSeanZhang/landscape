use libbpf_rs::TC_EGRESS;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;
use crate::runtime::EbpfRuntime;

mod tc_wan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_intro.skel.rs"));
}
use tc_wan_ingress_intro_skel::{TcWanIngressIntroSkel, TcWanIngressIntroSkelBuilder};

pub(crate) mod tc_wan_egress_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_route.skel.rs"));
}
use tc_wan_egress_route_skel::{TcWanEgressRouteSkel, TcWanEgressRouteSkelBuilder};

pub struct TcWanRouteHandle {
    // TrieTarget: the guard field drops before the skeleton field, so the
    // trie target is detached while the arena mmap is still alive.
    _intro_trie: crate::maps::wan_trie::dispatcher::TrieTarget<TcWanIngressIntroSkel<'static>>,
    _intro_backing: OwnedOpenObject,
    _egress_route_skel: TcWanEgressRouteSkel<'static>,
    _egress_route_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    egress_hook: Option<TcHookProxy>,
    _ifindex: u32,
}

unsafe impl Send for TcWanRouteHandle {}
unsafe impl Sync for TcWanRouteHandle {}

impl Drop for TcWanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        self.egress_hook.take();
    }
}

pub fn init_tc_wan_route(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_eth_header: bool,
    xdp_handoff_enabled: bool,
) -> LdEbpfResult<TcWanRouteHandle> {
    let paths = &rt.paths;

    let l3_offset: u32 = if has_eth_header { 14 } else { 0 };

    let (intro_backing, obj) = OwnedOpenObject::new();
    let builder = TcWanIngressIntroSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open per-if tc_wan_ingress_intro")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = xdp_handoff_enabled;
    crate::maps::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_pipe_root_progs,
        &paths.tc_pipe_root_progs_path(),
    );
    let intro_skel = bpf_ctx!(open_skel.load(), "load per-if tc_wan_ingress_intro")?;

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
        libbpf_rs::TC_INGRESS,
        1,
    );
    ingress_hook.attach();

    let (egress_route_backing, egress_obj) = OwnedOpenObject::new();
    let builder = TcWanEgressRouteSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(egress_obj), "open per-if tc_wan_egress_route")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    crate::maps::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_wan_egress_roots,
        &paths.tc_wan_egress_roots_path(),
    );
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
        "tc_wan_egress pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_v6_ll_chain, &paths.wan_v6_ll_chain),
        "tc_wan_egress pin wan_v6_ll_chain"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "tc_wan_egress pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "tc_wan_egress pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "tc_wan_egress pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map),
        "tc_wan_egress pin rt4_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map),
        "tc_wan_egress pin rt6_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "tc_wan_egress pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "tc_wan_egress pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "tc_wan_egress pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "tc_wan_egress pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "tc_wan_egress pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "tc_wan_egress pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "tc_wan_egress pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "tc_wan_egress pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
        "tc_wan_egress pin xdp_redirect_able"
    )?;
    let egress_route_skel = bpf_ctx!(open_skel.load(), "load per-if tc_wan_egress_route")?;
    let mut egress_hook = TcHookProxy::new(
        &egress_route_skel.progs.tc_wan_egress_route,
        ifindex as i32,
        TC_EGRESS,
        1,
    );
    egress_hook.attach();

    Ok(TcWanRouteHandle {
        _intro_trie: intro_trie,
        _intro_backing: intro_backing,
        _egress_route_skel: egress_route_skel,
        _egress_route_backing: egress_route_backing,
        ingress_hook: Some(ingress_hook),
        egress_hook: Some(egress_hook),
        _ifindex: ifindex,
    })
}
