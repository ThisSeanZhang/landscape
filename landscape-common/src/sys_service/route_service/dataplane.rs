//! System route table sync: push LAN prefixes and per-flow WAN target
//! slots into the eBPF route maps, sync the kernel default route, and
//! invalidate verdict caches.

use crate::config::FlowId;

use super::{LanRouteInfo, RouteTargetInfo, WanRouteTarget};

/// eBPF capability for the IP route service.
#[async_trait::async_trait]
pub trait RouteTableDataplane: Send + Sync {
    /// Add or update a LAN route entry (also invalidates the LAN
    /// verdict cache when the entry changes).
    fn add_lan_route(&self, info: LanRouteInfo);

    /// Remove a LAN route entry.
    fn del_lan_route(&self, info: LanRouteInfo);

    /// Replace the IPv4 WAN target slots of `flow_id` with the weighted
    /// `targets`.
    fn replace_wan_slots_v4(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]);

    /// Replace the IPv6 WAN target slots of `flow_id`.
    fn replace_wan_slots_v6(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]);

    /// Drop all IPv4 WAN target slots of `flow_id`.
    fn del_wan_slots_v4(&self, flow_id: FlowId);

    /// Drop all IPv6 WAN target slots of `flow_id`.
    fn del_wan_slots_v6(&self, flow_id: FlowId);

    /// Replace the kernel IPv4 default route with the weighted nexthops
    /// derived from the WAN route state; an empty slice leaves the kernel
    /// default route untouched (landscape never deletes a route it may not
    /// own). Returns `false` when the sync failed and should be retried.
    async fn sync_kernel_default_ipv4(&self, nexthops: &[RouteTargetInfo]) -> bool;

    /// Replace the kernel IPv6 default route with the weighted nexthops
    /// derived from the WAN route state; an empty slice leaves the kernel
    /// default route untouched. Returns `false` when the sync failed and
    /// should be retried.
    async fn sync_kernel_default_ipv6(&self, nexthops: &[RouteTargetInfo]) -> bool;

    /// Synchronize per-WAN-link kernel IPv4 policy routes (`ip rule` +
    /// dedicated routing table) used by `SkipRoute`-marked local sockets
    /// such as WAN health-check probes. Unlike `sync_kernel_default_ipv4`, an
    /// empty slice cleans up stale managed policy rules and tables. Returns
    /// `false` when any update failed and should be retried.
    async fn sync_kernel_wan_policy_ipv4(&self, targets: &[WanRouteTarget]) -> bool {
        let _ = targets;
        true
    }

    /// Recreate the LAN verdict-cache inner maps (invalidate all cached
    /// verdicts).
    fn invalidate_lan_cache(&self);
}

/// No-op implementation for tests.
pub struct NoopRouteTableDataplane;

#[async_trait::async_trait]
impl RouteTableDataplane for NoopRouteTableDataplane {
    fn add_lan_route(&self, _info: LanRouteInfo) {}

    fn del_lan_route(&self, _info: LanRouteInfo) {}

    fn replace_wan_slots_v4(&self, _flow_id: FlowId, _targets: &[(WanRouteTarget, u32)]) {}

    fn replace_wan_slots_v6(&self, _flow_id: FlowId, _targets: &[(WanRouteTarget, u32)]) {}

    fn del_wan_slots_v4(&self, _flow_id: FlowId) {}

    fn del_wan_slots_v6(&self, _flow_id: FlowId) {}

    async fn sync_kernel_default_ipv4(&self, _nexthops: &[RouteTargetInfo]) -> bool {
        true
    }

    async fn sync_kernel_default_ipv6(&self, _nexthops: &[RouteTargetInfo]) -> bool {
        true
    }

    async fn sync_kernel_wan_policy_ipv4(&self, _targets: &[WanRouteTarget]) -> bool {
        true
    }

    fn invalidate_lan_cache(&self) {}
}
