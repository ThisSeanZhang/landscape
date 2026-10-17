use libbpf_rs::TC_INGRESS;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{OwnedOpenObject, TcHookProxy, pin_and_reuse_map};
use crate::runtime::EbpfRuntime;
use crate::xdp_attach::NativeXdpLink;

use crate::skel::xdp_lan_route::XdpLanRouteSkelBuilder;

use crate::skel::tc_lan_ingress_route::TcLanIngressRouteSkelBuilder;

pub struct XdpLanRouteHandle {
    _link: NativeXdpLink,
    _skel: crate::skel::xdp_lan_route::XdpLanRouteSkel<'static>,
    _backing: OwnedOpenObject,
    _intro_skel: crate::skel::tc_lan_ingress_route::TcLanIngressRouteSkel<'static>,
    _intro_backing: OwnedOpenObject,
    ingress_hook: Option<TcHookProxy>,
    _ifindex: u32,
}

unsafe impl Send for XdpLanRouteHandle {}
unsafe impl Sync for XdpLanRouteHandle {}

impl Drop for XdpLanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
    }
}

pub fn init_xdp_lan_route(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_eth_header: bool,
) -> LdEbpfResult<XdpLanRouteHandle> {
    let paths = &rt.paths;
    let l3_offset: u32 = if has_eth_header { 14 } else { 0 };

    // ── XDP lan route ──

    let builder = XdpLanRouteSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_route skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        ),
        "xdp_lan_route pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path(),),
        "xdp_lan_route pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path(),),
        "xdp_lan_route pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_lan_route pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
        "xdp_lan_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "xdp_lan_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "xdp_lan_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "xdp_lan_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map,),
        "xdp_lan_route pin rt4_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map,),
        "xdp_lan_route pin rt6_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "xdp_lan_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "xdp_lan_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "xdp_lan_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "xdp_lan_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "xdp_lan_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "xdp_lan_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "xdp_lan_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "xdp_lan_route pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
        "xdp_lan_route pin xdp_redirect_able"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_route skeleton")?;

    let link = rt.xdp_attach().attach_native(&skel.progs.xdp_lan_route, ifindex)?;

    // LAN ifaces carry no chains of their own: xdp_lan_route is attached
    // directly and reaches the WAN link chains through the tail-call
    // arrays, whose roots the WAN link hub owns.

    // ── TC ingress intro (XDP handoff + normal TC processing) ──

    let (intro_backing, intro_obj) = OwnedOpenObject::new();
    let intro_builder = TcLanIngressRouteSkelBuilder::default();
    let mut intro_open_skel = bpf_ctx!(intro_builder.open(intro_obj), "open tc_lan_ingress_route")?;

    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    intro_open_skel.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = true;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow_match_map, &paths.flow_match_map),
        "tc_lan_ingress_route pin flow_match_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.wan_ip_binding, &paths.wan_ip),
        "tc_lan_ingress_route pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
        "tc_lan_ingress_route pin rt4_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
        "tc_lan_ingress_route pin rt6_lan_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt4_slot_map, &paths.rt4_slot_map,),
        "tc_lan_ingress_route pin rt4_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt6_slot_map, &paths.rt6_slot_map,),
        "tc_lan_ingress_route pin rt6_slot_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
        "tc_lan_ingress_route pin flow4_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
        "tc_lan_ingress_route pin flow6_dns_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
        "tc_lan_ingress_route pin flow4_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
        "tc_lan_ingress_route pin flow6_ip_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
        "tc_lan_ingress_route pin rt4_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
        "tc_lan_ingress_route pin rt6_cache_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
        "tc_lan_ingress_route pin ip_mac_v4"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
        "tc_lan_ingress_route pin ip_mac_v6"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut intro_open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able,),
        "tc_lan_ingress_route pin xdp_redirect_able"
    )?;

    let intro_skel = bpf_ctx!(intro_open_skel.load(), "load tc_lan_ingress_route")?;

    let mut ingress_hook = TcHookProxy::new(
        &intro_skel.progs.tc_lan_ingress_route,
        ifindex as i32,
        TC_INGRESS,
        crate::TC_LAN_INGRESS_INTRO_PRIORITY,
    );
    ingress_hook.attach();

    Ok(XdpLanRouteHandle {
        _link: link,
        _skel: skel,
        _backing: backing,
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        _ifindex: ifindex,
    })
}
