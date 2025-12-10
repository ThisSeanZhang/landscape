use std::mem::MaybeUninit;

pub(crate) mod flow_lan_bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/flow_lan.skel.rs"));
}

use flow_lan_bpf::*;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS, TC_INGRESS,
};
use tokio::sync::oneshot;

use crate::{
    bpf_error::LdEbpfResult, landscape::TcHookProxy, MAP_PATHS, WAN_ROUTE_EGRESS_PRIORITY,
    WAN_ROUTE_INGRESS_PRIORITY,
};

pub fn wan_route_attach(
    ifindex: u32,
    has_mac: bool,
    service_status: oneshot::Receiver<()>,
) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let firewall_builder = FlowLanSkelBuilder::default();
    let mut open_skel = firewall_builder.open(&mut open_object)?;

    // 检索匹配规则 MAP
    open_skel.maps.flow_match_map.set_pin_path(&MAP_PATHS.flow_match_map)?;
    open_skel.maps.flow_match_map.reuse_pinned_map(&MAP_PATHS.flow_match_map)?;

    open_skel.maps.rt_lan_map.set_pin_path(&MAP_PATHS.rt_lan_map)?;
    open_skel.maps.rt_lan_map.reuse_pinned_map(&MAP_PATHS.rt_lan_map)?;

    open_skel.maps.rt_target_map.set_pin_path(&MAP_PATHS.rt_target_map)?;
    open_skel.maps.rt_target_map.reuse_pinned_map(&MAP_PATHS.rt_target_map)?;

    open_skel.maps.flow_v_dns_map.set_pin_path(&MAP_PATHS.flow_verdict_dns_map)?;
    open_skel.maps.flow_v_dns_map.reuse_pinned_map(&MAP_PATHS.flow_verdict_dns_map)?;

    open_skel.maps.flow_v_ip_map.set_pin_path(&MAP_PATHS.flow_verdict_ip_map)?;
    open_skel.maps.flow_v_ip_map.reuse_pinned_map(&MAP_PATHS.flow_verdict_ip_map)?;

    open_skel.maps.wan_ipv4_binding.set_pin_path(&MAP_PATHS.wan_ip)?;
    open_skel.maps.wan_ipv4_binding.reuse_pinned_map(&MAP_PATHS.wan_ip)?;

    open_skel.maps.rt_cache_map.set_pin_path(&MAP_PATHS.rt_cache_map)?;
    open_skel.maps.rt_cache_map.reuse_pinned_map(&MAP_PATHS.rt_cache_map)?;

    open_skel.maps.debug_counter.set_pin_path(&MAP_PATHS.debug_counter)?;
    open_skel.maps.debug_counter.reuse_pinned_map(&MAP_PATHS.debug_counter)?;

    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    let skel = open_skel.load()?;

    let wan_route_ingress = skel.progs.wan_route_ingress;
    let wan_route_egress = skel.progs.wan_route_egress;

    let mut wan_route_ingress_hook = TcHookProxy::new(
        &wan_route_ingress,
        ifindex as i32,
        TC_INGRESS,
        WAN_ROUTE_INGRESS_PRIORITY,
    );

    let mut wan_route_egress_hook =
        TcHookProxy::new(&wan_route_egress, ifindex as i32, TC_EGRESS, WAN_ROUTE_EGRESS_PRIORITY);

    wan_route_ingress_hook.attach();
    wan_route_egress_hook.attach();

    let _ = service_status.blocking_recv();

    drop(wan_route_ingress_hook);
    drop(wan_route_egress_hook);
    Ok(())
}
