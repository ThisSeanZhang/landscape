//! Bridge between [`EbpfRuntime`] and the narrow capability traits
//! defined in `landscape-common`.
//!
//! Each consumer-facing trait gets one `Ebpf*` implementation here that
//! captures the runtime (a cheap bundle of `Arc`s) and delegates to the
//! internal Phase-1 APIs.  Attached dataplane state crosses the
//! boundary as `Box<dyn DataplaneGuard>`: dropping it tears the state
//! down.

use std::sync::Arc;

use crate::maps;
use crate::runtime::EbpfRuntime;
use landscape_common::ebpf::DataplaneGuard;
use landscape_common::flow::dataplane::FlowRuleDataplane;
use landscape_common::lan_service::lan_route::dataplane::LanRouteDataplane;
use landscape_common::lan_service::mac_binding::MacBindingDataplane;
use landscape_common::net::MacAddr;
use landscape_common::sys_service::route_service::dataplane::RouteTableDataplane;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::pppoe::PppoeDataplane;
use landscape_common::wan_service::pppoe::PppoeEgressTmpl;
use landscape_common::wan_service::wan_route::dataplane::WanRouteDataplane;

// ─────────────────────────────────────────────────────────────────────────
// Guard impls: every attach-style handle is a valid opaque guard.
// ─────────────────────────────────────────────────────────────────────────

impl DataplaneGuard for crate::stages::firewall::FirewallHandle {}
impl DataplaneGuard for crate::stages::nat::NatHandle {}
impl DataplaneGuard for crate::stages::mss::MssHandle {}
impl DataplaneGuard for crate::pppoe::pppoe_handle::PppoeHandle {}
impl DataplaneGuard for crate::chain::tc_lan_route::TcLanRouteHandle {}
impl DataplaneGuard for crate::chain::xdp_lan_intro::XdpLanIntroHandle {}
impl DataplaneGuard for crate::chain::tc_wan_route::TcWanRouteHandle {}
impl DataplaneGuard for crate::chain::xdp_wan_route::XdpWanRouteHandle {}

// ─────────────────────────────────────────────────────────────────────────
// PPPoE
// ─────────────────────────────────────────────────────────────────────────

/// The skeleton-side template type generated from the BPF C header.
type BpfPppoeTmpl = crate::pppoe::pppoe_handle::PppoeEgressTmpl;

/// The common and BPF-side templates must stay layout-identical; the
/// field-by-field conversion below relies on it.
const _: () = {
    assert!(std::mem::size_of::<PppoeEgressTmpl>() == std::mem::size_of::<BpfPppoeTmpl>(),);
};

fn to_bpf_tmpl(tmpl: &PppoeEgressTmpl) -> BpfPppoeTmpl {
    BpfPppoeTmpl {
        dmac: tmpl.dmac,
        smac: tmpl.smac,
        eth_proto: tmpl.eth_proto,
        ver_type: tmpl.ver_type,
        code: tmpl.code,
        session_id: tmpl.session_id,
        length: tmpl.length,
        protocol: tmpl.protocol,
    }
}

pub struct EbpfPppoeDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfPppoeDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl PppoeDataplane for EbpfPppoeDataplane {
    fn attach_session(
        &self,
        ifindex: u32,
        tmpl: PppoeEgressTmpl,
        mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::pppoe::pppoe_handle::create_pppoe_handle(
            self.rt.clone(),
            ifindex,
            to_bpf_tmpl(&tmpl),
            mtu,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
    }

    fn bind_wan_ipv4(
        &self,
        ifindex: u32,
        addr: std::net::Ipv4Addr,
        gateway: Option<std::net::Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        maps::wan::add_ipv4_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
    }

    fn unbind_wan_ipv4(&self, ifindex: u32) {
        maps::wan::del_ipv4_wan_ip(&self.rt.paths, ifindex);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// WAN address binding
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfWanAddrBinding {
    rt: Arc<EbpfRuntime>,
}

impl EbpfWanAddrBinding {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl WanAddrBinding for EbpfWanAddrBinding {
    fn bind_ipv4(
        &self,
        ifindex: u32,
        addr: std::net::Ipv4Addr,
        gateway: Option<std::net::Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        maps::wan::add_ipv4_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
    }

    fn unbind_ipv4(&self, ifindex: u32) {
        maps::wan::del_ipv4_wan_ip(&self.rt.paths, ifindex);
    }

    fn bind_ipv6(
        &self,
        ifindex: u32,
        addr: std::net::Ipv6Addr,
        gateway: Option<std::net::Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        maps::wan::add_ipv6_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
    }

    fn unbind_ipv6(&self, ifindex: u32) {
        maps::wan::del_ipv6_wan_ip(&self.rt.paths, ifindex);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Firewall
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfFirewallDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfFirewallDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl FirewallDataplane for EbpfFirewallDataplane {
    fn attach(&self, ifindex: u32, has_mac: bool) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::stages::firewall::init_firewall(&self.rt, ifindex, has_mac)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn sync_blacklist(
        &self,
        new_ips: Vec<landscape_common::flow::ip_mark::IpConfig>,
        old_ips: Vec<landscape_common::flow::ip_mark::IpConfig>,
    ) {
        maps::firewall::sync_firewall_blacklist(&self.rt.paths, new_ips, old_ips);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// NAT
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfNatDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfNatDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl NatDataplane for EbpfNatDataplane {
    fn attach(
        &self,
        ifindex: u32,
        has_mac: bool,
        config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::stages::nat::init_nat(&self.rt, ifindex, has_mac, config)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn sync_static_nat4(
        &self,
        configs: &[landscape_common::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config],
    ) {
        if let Err(e) = maps::nat::reconcile_static_nat4_map(&self.rt.paths, configs) {
            tracing::error!("reconcile static nat4 map error: {e:?}");
        }
    }

    fn sync_static_nat6(
        &self,
        configs: &[landscape_common::config_service::static_nat::config6::RuntimeStaticNatMappingV6Config],
    ) {
        if let Err(e) = maps::nat::reconcile_static_nat6_map(&self.rt.paths, configs) {
            tracing::error!("reconcile static nat6 map error: {e:?}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// MSS clamp
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfMssClampDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfMssClampDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl MssClampDataplane for EbpfMssClampDataplane {
    fn attach(
        &self,
        ifindex: u32,
        mtu: u16,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::stages::mss::init_mss(&self.rt, ifindex, mtu, has_mac)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// LAN route chains
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfLanRouteDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfLanRouteDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl LanRouteDataplane for EbpfLanRouteDataplane {
    fn install_xdp_intro(
        &self,
        ifindex: u32,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::xdp_lan_intro::init_xdp_lan_intro(&self.rt, ifindex, has_mac)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn install_tc_route(
        &self,
        ifindex: u32,
        has_mac: bool,
        xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::tc_lan_route::init_tc_lan_route(
            &self.rt,
            ifindex,
            has_mac,
            xdp_handoff_enabled,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
    }

    fn remove_xdp_roots(&self, ifindex: u32) {
        self.rt.xdp.remove_roots(ifindex);
    }

    fn set_redirect_able(&self, ifindex: u32, able: bool) {
        maps::redirect_able::set_xdp_redirect_able(&self.rt.paths, ifindex, able);
    }

    fn del_redirect_able(&self, ifindex: u32) {
        maps::redirect_able::del_xdp_redirect_able(&self.rt.paths, ifindex);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// WAN route chains
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfWanRouteDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfWanRouteDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl WanRouteDataplane for EbpfWanRouteDataplane {
    fn install_xdp_route(
        &self,
        ifindex: u32,
        has_mac: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::xdp_wan_route::init_xdp_wan_route(&self.rt, ifindex, has_mac)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn install_tc_route(
        &self,
        ifindex: u32,
        has_mac: bool,
        xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::tc_wan_route::init_tc_wan_route(
            &self.rt,
            ifindex,
            has_mac,
            xdp_handoff_enabled,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
    }

    fn remove_xdp_roots(&self, ifindex: u32) {
        self.rt.xdp.remove_roots(ifindex);
    }

    fn set_redirect_able(&self, ifindex: u32, able: bool) {
        maps::redirect_able::set_xdp_redirect_able(&self.rt.paths, ifindex, able);
    }

    fn del_redirect_able(&self, ifindex: u32) {
        maps::redirect_able::del_xdp_redirect_able(&self.rt.paths, ifindex);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// System route table
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfRouteTableDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfRouteTableDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl RouteTableDataplane for EbpfRouteTableDataplane {
    fn add_lan_route(&self, info: landscape_common::sys_service::route_service::LanRouteInfo) {
        maps::route::add_lan_route(&self.rt.paths, info);
    }

    fn del_lan_route(&self, info: landscape_common::sys_service::route_service::LanRouteInfo) {
        maps::route::del_lan_route(&self.rt.paths, info);
    }

    fn replace_wan_slots_v4(
        &self,
        flow_id: u32,
        targets: &[(landscape_common::sys_service::route_service::RouteTargetInfo, u32)],
    ) {
        maps::route::replace_wan_route_slots_v4(&self.rt.paths, flow_id, targets);
    }

    fn replace_wan_slots_v6(
        &self,
        flow_id: u32,
        targets: &[(landscape_common::sys_service::route_service::RouteTargetInfo, u32)],
    ) {
        maps::route::replace_wan_route_slots_v6(&self.rt.paths, flow_id, targets);
    }

    fn del_wan_slots_v4(&self, flow_id: u32) {
        maps::route::del_wan_route_slots_v4(&self.rt.paths, flow_id);
    }

    fn del_wan_slots_v6(&self, flow_id: u32) {
        maps::route::del_wan_route_slots_v6(&self.rt.paths, flow_id);
    }

    fn invalidate_lan_cache(&self) {
        maps::route::cache::recreate_route_lan_cache_inner_map(&self.rt.paths);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Flow rules
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfFlowRuleDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfFlowRuleDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl FlowRuleDataplane for EbpfFlowRuleDataplane {
    fn sync_flow_matches(&self, configs: &[landscape_common::flow::RuntimeFlowConfig]) {
        if let Err(e) = maps::flow::reconcile_flow_match_map(&self.rt.paths, configs) {
            tracing::error!("reconcile flow match map error: {e:?}");
        }
    }

    fn set_dst_ip_marks(
        &self,
        flow_id: u32,
        ips: Vec<landscape_common::flow::ip_mark::IpMarkInfo>,
    ) {
        maps::flow_wanip::add_wan_ip_mark(&self.rt.paths, flow_id, ips);
    }

    fn invalidate_lan_cache(&self) {
        maps::route::cache::recreate_route_lan_cache_inner_map(&self.rt.paths);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Neighbor MAC learning
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfMacBindingDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfMacBindingDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl MacBindingDataplane for EbpfMacBindingDataplane {
    fn learn_ipv4(&self, ifindex: u32, ip: std::net::Ipv4Addr, mac: MacAddr, dev_mac: MacAddr) {
        if let Err(e) = maps::mac::upsert_ipv4_ip_mac(&self.rt.paths, ifindex, ip, mac, dev_mac) {
            tracing::error!("upsert ipv4 ip_mac binding error: {e:?}");
        }
    }

    fn learn_ipv6(&self, ifindex: u32, ip: std::net::Ipv6Addr, mac: MacAddr, dev_mac: MacAddr) {
        if let Err(e) = maps::mac::upsert_ipv6_ip_mac(&self.rt.paths, ifindex, ip, mac, dev_mac) {
            tracing::error!("upsert ipv6 ip_mac binding error: {e:?}");
        }
    }
}
