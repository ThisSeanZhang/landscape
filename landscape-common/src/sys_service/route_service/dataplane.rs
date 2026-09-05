//! System route table sync: push LAN prefixes and per-flow WAN target
//! slots into the eBPF route maps and invalidate verdict caches.

use crate::config::FlowId;

use super::{LanRouteInfo, RouteTargetInfo};

/// eBPF capability for the IP route service.
pub trait RouteTableDataplane: Send + Sync {
    /// Add or update a LAN route entry (also invalidates the LAN
    /// verdict cache when the entry changes).
    fn add_lan_route(&self, info: LanRouteInfo);

    /// Remove a LAN route entry.
    fn del_lan_route(&self, info: LanRouteInfo);

    /// Replace the IPv4 WAN target slots of `flow_id` with the weighted
    /// `targets`.
    fn replace_wan_slots_v4(&self, flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]);

    /// Replace the IPv6 WAN target slots of `flow_id`.
    fn replace_wan_slots_v6(&self, flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]);

    /// Drop all IPv4 WAN target slots of `flow_id`.
    fn del_wan_slots_v4(&self, flow_id: FlowId);

    /// Drop all IPv6 WAN target slots of `flow_id`.
    fn del_wan_slots_v6(&self, flow_id: FlowId);

    /// Recreate the LAN verdict-cache inner maps (invalidate all cached
    /// verdicts).
    fn invalidate_lan_cache(&self);
}

/// No-op implementation for tests.
pub struct NoopRouteTableDataplane;

impl RouteTableDataplane for NoopRouteTableDataplane {
    fn add_lan_route(&self, _info: LanRouteInfo) {}

    fn del_lan_route(&self, _info: LanRouteInfo) {}

    fn replace_wan_slots_v4(&self, _flow_id: FlowId, _targets: &[(RouteTargetInfo, u32)]) {}

    fn replace_wan_slots_v6(&self, _flow_id: FlowId, _targets: &[(RouteTargetInfo, u32)]) {}

    fn del_wan_slots_v4(&self, _flow_id: FlowId) {}

    fn del_wan_slots_v6(&self, _flow_id: FlowId) {}

    fn invalidate_lan_cache(&self) {}
}
