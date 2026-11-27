//! Flow-config → WAN target slot join.
//!
//! The flow side owns the configs and pushes them in via
//! [`IpRouteService::sync_flow_wan_targets`] after config changes and on
//! every [`WanRouteEvent`](super::WanRouteEvent); the join itself lives here
//! next to the WAN state it reads.

use std::collections::HashMap;

use landscape_common::{
    config::FlowId,
    flow::{FlowTarget, config::FlowConfig},
    sys_service::route_service::{RouteOwner, WanRouteTarget, dataplane::RouteTableDataplane},
};

use super::{
    IpRouteService, WanRoutesByOwner,
    health::{LinkHealths, is_owner_available},
};

fn route_owner_of(target: &FlowTarget) -> RouteOwner {
    match target {
        FlowTarget::Interface { link_id, .. } => RouteOwner::Link(*link_id),
        FlowTarget::Netns { container_name } => RouteOwner::Netns(container_name.clone()),
    }
}

fn filter_healthy_flow_targets(
    flow_id: FlowId,
    resolved: Vec<(RouteOwner, WanRouteTarget, u32)>,
    link_healths: &LinkHealths,
) -> Vec<(WanRouteTarget, u32)> {
    // Only filter unhealthy links when a flow has >= 2 resolved targets
    // (e.g. ECMP flows). Single-target isolated flows keep their resolved
    // target (never leaking to other WANs), and multi-target flows fail open
    // when every positive-weight target is Unhealthy so a probe target outage
    // cannot blackhole the entire flow.
    if resolved.len() >= 2 {
        let available: Vec<(WanRouteTarget, u32)> = resolved
            .iter()
            .filter(|(owner, _, _)| is_owner_available(link_healths, owner))
            .map(|(_, route, weight)| (route.clone(), *weight))
            .collect();
        if available.iter().any(|(_, weight)| *weight > 0) {
            if available.len() < resolved.len() {
                tracing::warn!(
                    flow_id,
                    total_targets = resolved.len(),
                    healthy_targets = available.len(),
                    "filtering unhealthy WAN link(s) from multi-target flow"
                );
            }
            return available;
        }
        tracing::warn!(
            flow_id,
            total_targets = resolved.len(),
            "all targets in flow are unhealthy; failing open with resolved targets"
        );
    }

    resolved.into_iter().map(|(_, route, weight)| (route, weight)).collect()
}

pub(super) fn collect_target_refresh_result(
    flow_configs: &[FlowConfig],
    wan_infos: &WanRoutesByOwner,
    link_healths: &LinkHealths,
) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
    let mut result = HashMap::new();

    for flow_config in flow_configs {
        let targets = if flow_config.enable {
            let resolved: Vec<(RouteOwner, WanRouteTarget, u32)> = flow_config
                .flow_targets
                .iter()
                .filter_map(|target| {
                    let owner = route_owner_of(&target.target);
                    wan_infos.get(&owner).cloned().map(|route| (owner, route, target.weight))
                })
                .collect();
            filter_healthy_flow_targets(flow_config.flow_id, resolved, link_healths)
        } else {
            Vec::new()
        };

        result.insert(flow_config.flow_id, targets);
    }

    result
}

fn warn_fully_unresolved_flows(
    flow_configs: &[FlowConfig],
    ipv4_result: &HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
    ipv6_result: &HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    for flow_config in flow_configs {
        if !flow_config.enable || flow_config.flow_targets.is_empty() {
            continue;
        }
        let unresolved = |result: &HashMap<FlowId, Vec<_>>| {
            result.get(&flow_config.flow_id).is_none_or(|t| t.is_empty())
        };
        if unresolved(ipv4_result) && unresolved(ipv6_result) {
            tracing::warn!(
                flow_id = flow_config.flow_id,
                "flow targets resolve to no WAN route in either address family; the flow's traffic is dropped until its link returns"
            );
        }
    }
}

fn apply_ipv4_target_refresh_result(
    dataplane: &dyn RouteTableDataplane,
    result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    tracing::info!("ipv4 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            dataplane.del_wan_slots_v4(flow_id);
        } else {
            dataplane.replace_wan_slots_v4(flow_id, &configs);
        }
    }
}

fn apply_ipv6_target_refresh_result(
    dataplane: &dyn RouteTableDataplane,
    result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
) {
    tracing::info!("ipv6 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            dataplane.del_wan_slots_v6(flow_id);
        } else {
            dataplane.replace_wan_slots_v6(flow_id, &configs);
        }
    }
}

impl IpRouteService {
    /// Recompute the per-flow WAN target slots for `flow_configs` against the
    /// current WAN route and link-health state and sync them into the eBPF maps.
    pub async fn sync_flow_wan_targets(&self, flow_configs: &[FlowConfig]) {
        let _sync_guard = self.flow_target_sync_lock.lock().await;
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        let link_healths = self.clone_link_healths().await;

        let ipv4_result =
            collect_target_refresh_result(flow_configs, &ipv4_wan_infos, &link_healths);
        let ipv6_result =
            collect_target_refresh_result(flow_configs, &ipv6_wan_infos, &link_healths);

        warn_fully_unresolved_flows(flow_configs, &ipv4_result, &ipv6_result);

        apply_ipv4_target_refresh_result(&*self.dataplane, ipv4_result);
        apply_ipv6_target_refresh_result(&*self.dataplane, ipv6_result);

        self.dataplane.invalidate_lan_cache();
    }

    /// Drop all WAN target slots of `flow_id` (e.g. after the flow config is
    /// deleted).
    pub fn clear_flow_wan_targets(&self, flow_id: FlowId) {
        self.dataplane.del_wan_slots_v4(flow_id);
        self.dataplane.del_wan_slots_v6(flow_id);
        self.dataplane.invalidate_lan_cache();
    }
}
