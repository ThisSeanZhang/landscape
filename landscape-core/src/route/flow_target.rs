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
    sys_service::route_service::{RouteTargetInfo, dataplane::RouteTableDataplane},
};

use super::{IpRouteService, WanRoutesByOwner};

fn find_route_target<'a>(
    wan_infos: &'a WanRoutesByOwner,
    target: &FlowTarget,
) -> Option<&'a RouteTargetInfo> {
    match target {
        FlowTarget::Interface { name, .. } => wan_infos.get(name),
        FlowTarget::Netns { container_name } => wan_infos.get(container_name),
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
        apply_ipv4_target_refresh_result(
            &*self.dataplane,
            collect_target_refresh_result(flow_configs, &ipv4_wan_infos),
        );

        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        apply_ipv6_target_refresh_result(
            &*self.dataplane,
            collect_target_refresh_result(flow_configs, &ipv6_wan_infos),
        );

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
