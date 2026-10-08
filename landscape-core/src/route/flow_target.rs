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
    sys_service::route_service::{RouteOwner, RouteTargetInfo, dataplane::RouteTableDataplane},
};

use super::{IpRouteService, WanRoutesByOwner};

fn find_route_target<'a>(
    wan_infos: &'a WanRoutesByOwner,
    target: &FlowTarget,
) -> Option<&'a RouteTargetInfo> {
    match target {
        FlowTarget::Interface { link_id, .. } => wan_infos.get(&RouteOwner::Link(*link_id)),
        FlowTarget::Netns { container_name } => {
            wan_infos.get(&RouteOwner::Netns(container_name.clone()))
        }
    }
}

pub(super) fn collect_target_refresh_result(
    flow_configs: &[FlowConfig],
    wan_infos: &WanRoutesByOwner,
) -> HashMap<FlowId, Vec<(RouteTargetInfo, u32)>> {
    let mut result = HashMap::new();

    for flow_config in flow_configs {
        let targets = if flow_config.enable {
            flow_config
                .flow_targets
                .iter()
                .filter_map(|target| {
                    find_route_target(wan_infos, &target.target)
                        .cloned()
                        .map(|route| (route, target.weight))
                })
                .collect()
        } else {
            Vec::new()
        };

        result.insert(flow_config.flow_id, targets);
    }

    result
}

fn warn_fully_unresolved_flows(
    flow_configs: &[FlowConfig],
    ipv4_result: &HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>,
    ipv6_result: &HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>,
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
    result: HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>,
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
    result: HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>,
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
    /// current WAN route state and sync them into the eBPF maps.
    pub async fn sync_flow_wan_targets(&self, flow_configs: &[FlowConfig]) {
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let ipv4_result = collect_target_refresh_result(flow_configs, &ipv4_wan_infos);

        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        let ipv6_result = collect_target_refresh_result(flow_configs, &ipv6_wan_infos);

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
