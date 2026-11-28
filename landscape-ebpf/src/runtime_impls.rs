//! Bridge between [`EbpfRuntime`] and the narrow capability traits
//! defined in `landscape-common`.
//!
//! Each consumer-facing trait gets one `Ebpf*` implementation here that
//! captures the runtime (a cheap bundle of `Arc`s) and delegates to the
//! internal Phase-1 APIs.  Attached dataplane state crosses the
//! boundary as `Box<dyn DataplaneGuard>`: dropping it tears the state
//! down.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::maps;
use crate::runtime::EbpfRuntime;
use landscape_common::ebpf::DataplaneGuard;
use landscape_common::flow::dataplane::FlowRuleDataplane;
use landscape_common::lan_service::lan_ipv6::dataplane::Ip6DaoFilterDataplane;
use landscape_common::lan_service::lan_route::dataplane::LanRouteDataplane;
use landscape_common::lan_service::mac_binding::MacBindingDataplane;
use landscape_common::net::MacAddr;
use landscape_common::sys_service::route_service::dataplane::RouteTableDataplane;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::wan_route::dataplane::WanRouteDataplane;

// ─────────────────────────────────────────────────────────────────────────
// Guard impls: every attach-style handle is a valid opaque guard.
// ─────────────────────────────────────────────────────────────────────────

impl DataplaneGuard for crate::stages::firewall::FirewallHandle {}
impl DataplaneGuard for crate::stages::nat4::Nat4Handle {}
impl DataplaneGuard for crate::stages::nat6::Nat6Handle {}
impl DataplaneGuard for crate::stages::mss::MssHandle {}
impl DataplaneGuard for crate::pppoe::pppoe_handle::PppoeHandle {}
impl DataplaneGuard for crate::chain::tc_lan_route::TcLanRouteHandle {}
impl DataplaneGuard for crate::dao_ns::TcLanDaoHandle {}
impl DataplaneGuard for crate::chain::xdp_lan_route::XdpLanRouteHandle {}
impl DataplaneGuard for crate::chain::tc_wan_route::TcWanRouteHandle {}
impl DataplaneGuard for crate::chain::xdp_wan_route::XdpWanRouteHandle {}

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
    fn sync_static_nat4(
        &self,
        _configs: &[landscape_common::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config],
    ) {
        // The NAT4 stage reload re-seeds the napt maps from the repository.
        self.rt.notify_static_nat4();
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
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::xdp_lan_route::init_xdp_lan_route(&self.rt, ifindex, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn install_tc_route(
        &self,
        ifindex: u32,
        has_eth_header: bool,
        xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::tc_lan_route::init_tc_lan_route(
            &self.rt,
            ifindex,
            has_eth_header,
            xdp_handoff_enabled,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
    }

    fn set_redirect_able(&self, ifindex: u32, able: bool) {
        maps::redirect_able::set_xdp_redirect_able(&self.rt.paths, ifindex, able);
    }

    fn del_redirect_able(&self, ifindex: u32) {
        maps::redirect_able::del_xdp_redirect_able(&self.rt.paths, ifindex);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// LAN IPv6 DAD observer
// ─────────────────────────────────────────────────────────────────────────

pub struct EbpfIp6DaoFilterDataplane {
    rt: Arc<EbpfRuntime>,
}

impl EbpfIp6DaoFilterDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt }
    }
}

impl Ip6DaoFilterDataplane for EbpfIp6DaoFilterDataplane {
    fn install_tc_dao(&self, ifindex: u32) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::dao_ns::init_tc_lan_dao(&self.rt, ifindex)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
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
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::xdp_wan_route::init_xdp_wan_route(&self.rt, ifindex, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn install_tc_route(
        &self,
        ifindex: u32,
        has_eth_header: bool,
        xdp_handoff_enabled: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        crate::chain::tc_wan_route::init_tc_wan_route(
            &self.rt,
            ifindex,
            has_eth_header,
            xdp_handoff_enabled,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
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
    last_policy_chains: Mutex<BTreeSet<u16>>,
}

impl EbpfRouteTableDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self {
            rt,
            last_policy_chains: Mutex::new(BTreeSet::new()),
        }
    }
}

#[async_trait::async_trait]
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
        targets: &[(landscape_common::sys_service::route_service::WanRouteTarget, u32)],
    ) {
        maps::route::replace_wan_route_slots_v4(&self.rt.paths, flow_id, targets);
    }

    fn replace_wan_slots_v6(
        &self,
        flow_id: u32,
        targets: &[(landscape_common::sys_service::route_service::WanRouteTarget, u32)],
    ) {
        maps::route::replace_wan_route_slots_v6(&self.rt.paths, flow_id, targets);
    }

    fn del_wan_slots_v4(&self, flow_id: u32) {
        maps::route::del_wan_route_slots_v4(&self.rt.paths, flow_id);
    }

    fn del_wan_slots_v6(&self, flow_id: u32) {
        maps::route::del_wan_route_slots_v6(&self.rt.paths, flow_id);
    }

    fn set_flow_balance_mode(&self, flow_id: u32, mode: landscape_common::flow::FlowBalanceMode) {
        maps::route::set_flow_balance_mode(&self.rt.paths, flow_id, mode);
    }

    async fn sync_kernel_default_ipv4(
        &self,
        nexthops: &[landscape_common::sys_service::route_service::RouteTargetInfo],
    ) -> bool {
        // No WAN IPv4 default target: leave the kernel default route (if
        // any) untouched.
        if nexthops.is_empty() {
            return true;
        }

        run_kernel_default_sync("ipv4", &kernel_default_ipv4_args(nexthops)).await
    }

    async fn sync_kernel_default_ipv6(
        &self,
        nexthops: &[landscape_common::sys_service::route_service::RouteTargetInfo],
    ) -> bool {
        // No WAN IPv6 default target: leave the kernel default route (if
        // any) untouched.
        if nexthops.is_empty() {
            return true;
        }

        run_kernel_default_sync("ipv6", &kernel_default_ipv6_args(nexthops)).await
    }

    async fn sync_kernel_wan_policy_ipv4(
        &self,
        targets: &[landscape_common::sys_service::route_service::WanRouteTarget],
    ) -> bool {
        crate::wan_policy_route::sync_kernel_wan_policy_ipv4(targets, &self.last_policy_chains)
            .await
    }

    fn invalidate_lan_cache(&self) {
        maps::route::cache::recreate_route_lan_cache_inner_map(&self.rt.paths);
    }
}

/// Run `ip` for one family's kernel default route, logging the command and
/// any failure. Returns `true` only on success so the caller retries.
async fn run_kernel_default_sync(family: &str, args: &[String]) -> bool {
    tracing::info!("sync kernel default {family} route: {}", args.join(" "));
    match tokio::process::Command::new("ip").args(args).output().await {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            tracing::error!(
                "sync kernel default {family} route failed: {:?}",
                String::from_utf8_lossy(&output.stderr)
            );
            false
        }
        Err(e) => {
            tracing::error!("sync kernel default {family} route failed: {e:?}");
            false
        }
    }
}

/// Build the `ip` arguments for a kernel default route:
/// `<prefix> nexthop via G dev I weight W ...`. Point-to-point nexthops
/// marked `dev_only_nexthop` omit the `via` gateway. The slice is
/// non-empty: an empty target set is a no-op handled before this call.
fn kernel_default_route_args(
    prefix: &[&str],
    nexthops: &[landscape_common::sys_service::route_service::RouteTargetInfo],
) -> Vec<String> {
    let mut args: Vec<String> = prefix.iter().map(|arg| (*arg).to_string()).collect();
    for nexthop in nexthops {
        args.push("nexthop".to_string());
        if nexthop.dev_only_nexthop {
            args.push("dev".to_string());
        } else {
            args.push("via".to_string());
            args.push(nexthop.gateway_ip.to_string());
            args.push("dev".to_string());
        }
        args.push(nexthop.iface_name.clone());
        args.push("weight".to_string());
        args.push(nexthop.weight.to_string());
    }
    args
}

/// Build the `ip` arguments for the kernel IPv4 default route.
fn kernel_default_ipv4_args(
    nexthops: &[landscape_common::sys_service::route_service::RouteTargetInfo],
) -> Vec<String> {
    kernel_default_route_args(&["route", "replace", "default"], nexthops)
}

/// Build the `ip` arguments for the kernel IPv6 default route.
fn kernel_default_ipv6_args(
    nexthops: &[landscape_common::sys_service::route_service::RouteTargetInfo],
) -> Vec<String> {
    kernel_default_route_args(&["-6", "route", "replace", "default"], nexthops)
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

    fn set_dst_port_marks(
        &self,
        flow_id: u32,
        ports: Vec<landscape_common::flow::ip_mark::PortMarkInfo>,
    ) {
        maps::flow_wanip::set_dst_port_marks(&self.rt.paths, flow_id, ports);
    }

    fn invalidate_lan_cache(&self) {
        maps::route::cache::recreate_route_lan_cache_inner_map(&self.rt.paths);
        maps::route::cache::recreate_route_conn_inner_map(&self.rt.paths);
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

#[cfg(test)]
mod kernel_default_tests {
    use super::*;
    use landscape_common::sys_service::route_service::RouteTargetInfo;
    use std::net::Ipv4Addr;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn target(iface: &str, gateway: &str, weight: u32, dev_only: bool) -> RouteTargetInfo {
        let mut info = RouteTargetInfo::new_gateway_v4(
            1,
            iface,
            None,
            Ipv4Addr::new(192, 0, 2, 10),
            gateway.parse().unwrap(),
            true,
        );
        info.weight = weight;
        info.dev_only_nexthop = dev_only;
        info
    }

    #[test]
    fn single_via_nexthop() {
        let args = kernel_default_ipv4_args(&[target("eth0", "192.168.1.1", 1, false)]);
        assert_eq!(
            args,
            strs(&[
                "route",
                "replace",
                "default",
                "nexthop",
                "via",
                "192.168.1.1",
                "dev",
                "eth0",
                "weight",
                "1"
            ])
        );
    }

    #[test]
    fn mixed_ecmp_nexthops() {
        let args = kernel_default_ipv4_args(&[
            target("eth0", "192.168.1.1", 2, false),
            target("ppp0", "0.0.0.0", 1, true),
        ]);
        assert_eq!(
            args,
            strs(&[
                "route",
                "replace",
                "default",
                "nexthop",
                "via",
                "192.168.1.1",
                "dev",
                "eth0",
                "weight",
                "2",
                "nexthop",
                "dev",
                "ppp0",
                "weight",
                "1",
            ])
        );
    }
}
