//! IP route state service: tracks WAN/LAN route state, syncs it into the
//! eBPF route maps, and publishes change events.
//!
//! This service owns route state only; it never reads flow rules from the
//! database. Flow-side services push their configs in via
//! [`IpRouteService::sync_flow_wan_targets`] and subscribe to
//! [`WanRouteEvent`] to recompute per-flow WAN target slots.
//!
//! Module layout:
//! - [`wan`]: WAN route state + change events
//! - [`lan`]: LAN route state
//! - [`local_addr`]: reachable-local-address snapshots ([`LocalAddrView`])
//! - [`flow_target`]: flow-config → WAN target slot join

mod flow_target;
mod lan;
mod local_addr;
mod wan;

pub use local_addr::LocalAddrView;
pub use wan::{WanRouteEvent, WanRouteEventKind};

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use arc_swap::ArcSwap;
use landscape_common::sys_service::route_service::{
    LanIPv6RouteKey, LanRouteInfo, RouteOwner, RouteTargetInfo,
    dataplane::{NoopRouteTableDataplane, RouteTableDataplane},
};
use tokio::sync::{RwLock, broadcast};

pub(crate) type ShareRwLock<T> = Arc<RwLock<T>>;
// Reachable local addresses grouped by interface index.
pub(crate) type LocalAddrsByIfindex = HashMap<u32, Arc<Vec<IpAddr>>>;
// One owner (link / container) maps to one active WAN route target.
pub(crate) type WanRoutesByOwner = HashMap<RouteOwner, RouteTargetInfo>;
// One owner may publish multiple IPv4 LAN routes; same-subnet routes replace each other.
pub(crate) type Ipv4LanRoutesByOwner = HashMap<String, Vec<LanRouteInfo>>;
// Each IPv6 LAN route is keyed individually to support precise updates and removals.
pub(crate) type Ipv6LanRoutesByKey = HashMap<LanIPv6RouteKey, LanRouteInfo>;

#[derive(Clone)]
pub struct IpRouteService {
    pub(crate) dataplane: Arc<dyn RouteTableDataplane>,
    pub(crate) ipv4_wan_ifaces: ShareRwLock<WanRoutesByOwner>,
    pub(crate) ipv6_wan_ifaces: ShareRwLock<WanRoutesByOwner>,
    pub(crate) wan_route_events: broadcast::Sender<WanRouteEvent>,

    pub(crate) ipv4_lan_ifaces: ShareRwLock<Ipv4LanRoutesByOwner>,
    pub(crate) ipv6_lan_ifaces: ShareRwLock<Ipv6LanRoutesByKey>,
    pub(crate) reachable_local_ipv4_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    pub(crate) reachable_local_ipv4_addrs_by_ifindex: Arc<ArcSwap<LocalAddrsByIfindex>>,
    pub(crate) reachable_local_ipv6_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    pub(crate) reachable_local_ipv6_addrs_by_ifindex: Arc<ArcSwap<LocalAddrsByIfindex>>,
}

async fn clone_locked_state<T: Clone>(state: &ShareRwLock<T>) -> T {
    state.read().await.clone()
}

impl IpRouteService {
    pub fn new(dataplane: Arc<dyn RouteTableDataplane>) -> Self {
        IpRouteService {
            dataplane,
            ipv4_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            wan_route_events: broadcast::channel(64).0,
            ipv4_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            reachable_local_ipv4_addrs: Arc::new(ArcSwap::from_pointee(Vec::new())),
            reachable_local_ipv4_addrs_by_ifindex: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            reachable_local_ipv6_addrs: Arc::new(ArcSwap::from_pointee(Vec::new())),
            reachable_local_ipv6_addrs_by_ifindex: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }
}

/// Test-only helper: an [`IpRouteService`] backed by a no-op dataplane.
#[doc(hidden)]
pub fn test_used_ip_route() -> IpRouteService {
    IpRouteService::new(Arc::new(NoopRouteTableDataplane))
}

#[cfg(test)]
mod tests;
