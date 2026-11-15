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
    wan_link::WanLinkHealthState,
};

use super::{IpRouteService, LinkHealths, WanRoutesByOwner};
use uuid::Uuid;

fn find_route_target<'a>(
    wan_infos: &'a WanRoutesByOwner,
    target: &FlowTarget,
) -> Option<&'a WanRouteTarget> {
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
) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
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

/// Selection clocks are monotonic; wall time is used only for the status API.
#[derive(Default)]
pub(super) struct FailoverSelections {
    active: HashMap<(FlowId, bool), ActiveFailover>,
    pub(super) default_owner: Option<FlowId>,
    default_source_generation: HashMap<bool, u64>,
    published: HashMap<(FlowId, bool), Vec<(WanRouteTarget, u32)>>,
}

#[derive(Clone)]
struct ActiveFailover {
    order: Vec<Uuid>,
    selected: Option<Uuid>,
    selected_route: Option<WanRouteTarget>,
    generation: u64,
    selection_changed: bool,
    changed: std::time::Instant,
    unknown_since: HashMap<Uuid, std::time::Instant>,
    healthy_since: HashMap<Uuid, std::time::Instant>,
    /// Exits that may still carry sessions after a keep-existing switch.
    retained_routes: HashMap<Uuid, WanRouteTarget>,
    status: landscape_common::flow::failover::FlowWanStatus,
}

impl FailoverSelections {
    fn resolve(
        &mut self,
        configs: &[FlowConfig],
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
        ipv6: bool,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        self.resolve_at(configs, routes, health, ipv6, std::time::Instant::now())
    }

    fn resolve_at(
        &mut self,
        configs: &[FlowConfig],
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
        ipv6: bool,
        now: std::time::Instant,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        use landscape_common::flow::failover::{
            FlowWanCandidateStatus, FlowWanStatus, FlowWanSwitchEvent, WanSelectionReason as Reason,
        };
        use landscape_common::utils::time::now_ms;
        let mut result = collect_target_refresh_result(configs, routes);
        for config in configs {
            let key = (config.flow_id, ipv6);
            if !config.enable || !config.failover.ordered_targets() {
                self.active.remove(&key);
                continue;
            }
            let order: Vec<Uuid> = config
                .flow_targets
                .iter()
                .filter_map(|target| match target.target {
                    FlowTarget::Interface { link_id, .. } => Some(link_id),
                    FlowTarget::Netns { .. } => None,
                })
                .collect();
            let state = self.active.entry(key).or_insert_with(|| ActiveFailover {
                order: order.clone(),
                selected: None,
                selected_route: None,
                generation: now_ms().saturating_mul(1000),
                selection_changed: false,
                changed: now,
                unknown_since: HashMap::new(),
                healthy_since: HashMap::new(),
                retained_routes: HashMap::new(),
                status: FlowWanStatus {
                    flow_id: config.flow_id,
                    ipv6,
                    automatic: config.failover.enable,
                    trigger: config.failover.trigger,
                    active_link_id: None,
                    active_iface_name: None,
                    selected_at_ms: now_ms(),
                    reason: Reason::NoAvailableWan,
                    retry_after_secs: None,
                    candidates: vec![],
                    history: vec![],
                    router_policy_applied: None,
                    router_policy_error: None,
                    router_policy_checked_at_ms: None,
                    router_policy_cleanup: false,
                },
            });
            let reordered = state.order != order;
            let previous = state.selected;
            let has_route = |id: &Uuid| routes.contains_key(&RouteOwner::Link(*id));
            let probe_verdict =
                |id: &Uuid| health.get(id).map_or(WanLinkHealthState::Unknown, |info| info.state);
            let link_only =
                config.failover.trigger == landscape_common::flow::FlowFailoverTrigger::LinkState;
            let verdict =
                |id: &Uuid| if link_only { WanLinkHealthState::Healthy } else { probe_verdict(id) };
            if state.status.trigger != config.failover.trigger {
                state.unknown_since.clear();
                state.healthy_since.clear();
            }
            let healthy = |id: &Uuid| has_route(id) && verdict(id) == WanLinkHealthState::Healthy;
            for id in &order {
                if has_route(id) && verdict(id) == WanLinkHealthState::Unknown {
                    state.unknown_since.entry(*id).or_insert(now);
                } else {
                    state.unknown_since.remove(id);
                }
                if healthy(id) {
                    state.healthy_since.entry(*id).or_insert(now);
                } else {
                    state.healthy_since.remove(id);
                }
            }
            state.unknown_since.retain(|id, _| order.contains(id));
            state.healthy_since.retain(|id, _| order.contains(id));
            // A recovered primary only receives new connections. The old
            // backup can therefore still carry sessions even while it is no
            // longer the selected exit. Its later failure must honor the
            // failure policy, too. A changed route invalidates cached gateway/
            // ifindex data regardless of the keep-existing policy.
            let reset_retained = state.retained_routes.iter().any(|(id, old)| {
                let route = routes.get(&RouteOwner::Link(*id));
                let unknown_expired = !config.failover.fail_open_on_unknown
                    && state.unknown_since.get(id).is_some_and(|since| {
                        now.duration_since(*since).as_secs()
                            >= u64::from(config.failover.unknown_grace_secs)
                    });
                route.is_some_and(|route| route != old)
                    || (config.failover.failure_connection_policy
                        == landscape_common::flow::FlowConnectionPolicy::ResetExisting
                        && (route.is_none()
                            || verdict(id) == WanLinkHealthState::Unhealthy
                            || unknown_expired))
            });
            if reset_retained {
                state.generation = state.generation.wrapping_add(1);
                state.retained_routes.clear();
                tracing::info!(
                    flow_id = config.flow_id,
                    ipv6,
                    "invalidated retained WAN connections after an old exit failed or changed"
                );
            }
            let best = order.iter().copied().find(healthy);
            let mut retry_after_secs = None;
            let (selected, reason) = if !config.failover.enable {
                (order.first().copied().filter(has_route), Reason::ManualPrimary)
            } else if !reordered && previous.is_some_and(|id| healthy(&id)) {
                if !config.failover.auto_failback {
                    (previous, Reason::StickyBackup)
                } else if best != previous {
                    let candidate = best.expect("healthy current exit implies a healthy candidate");
                    let stable = now.duration_since(state.healthy_since[&candidate]).as_secs();
                    let held = now.duration_since(state.changed).as_secs();
                    let wait = u64::from(config.failover.failback_delay_secs)
                        .saturating_sub(stable)
                        .max(u64::from(config.failover.switch_hold_secs).saturating_sub(held));
                    if wait > 0 {
                        retry_after_secs = Some(wait);
                        (previous, Reason::WaitingFailback)
                    } else {
                        (best, Reason::Healthy)
                    }
                } else {
                    (previous, Reason::Healthy)
                }
            } else if best.is_some() {
                (best, Reason::Healthy)
            } else {
                // Only configured, routed Unknown links qualify; known failures never do.
                let unknown =
                    |id: &Uuid| has_route(id) && verdict(id) == WanLinkHealthState::Unknown;
                let remaining_grace = |id: &Uuid| {
                    u64::from(config.failover.unknown_grace_secs)
                        .saturating_sub(now.duration_since(state.unknown_since[id]).as_secs())
                };
                // A previously selected Unknown WAN may have exhausted its
                // grace while another candidate has only just become Unknown.
                // Prefer the longest remaining grace; preserve the current WAN
                // on ties, then the configured order to avoid needless churn.
                let candidate = order
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(_, id)| unknown(id))
                    .max_by_key(|(index, id)| {
                        (remaining_grace(id), Some(*id) == previous, std::cmp::Reverse(*index))
                    })
                    .map(|(_, id)| id);
                match candidate {
                    Some(id) => {
                        let elapsed = now.duration_since(state.unknown_since[&id]).as_secs();
                        let remaining =
                            u64::from(config.failover.unknown_grace_secs).saturating_sub(elapsed);
                        if remaining > 0 {
                            retry_after_secs = Some(remaining);
                            (Some(id), Reason::StartupGrace)
                        } else if config.failover.fail_open_on_unknown {
                            (Some(id), Reason::UnknownFailOpen)
                        } else {
                            (None, Reason::NoAvailableWan)
                        }
                    }
                    None => (None, Reason::NoAvailableWan),
                }
            };
            state.selection_changed = previous != selected;
            if reordered || (state.status.automatic && !config.failover.enable) {
                state.generation = state.generation.wrapping_add(1);
                state.retained_routes.clear();
            }
            if previous != selected {
                let recovery = !reordered && previous.is_some_and(|id| healthy(&id));
                let policy = if !config.failover.enable || reordered {
                    landscape_common::flow::FlowConnectionPolicy::ResetExisting
                } else if recovery {
                    config.failover.recovery_connection_policy
                } else {
                    config.failover.failure_connection_policy
                };
                if policy == landscape_common::flow::FlowConnectionPolicy::ResetExisting {
                    state.generation = state.generation.wrapping_add(1);
                    state.retained_routes.clear();
                } else if let Some(id) = previous
                    && let Some(route) = &state.selected_route
                {
                    state.retained_routes.insert(id, route.clone());
                }
                if let Some(id) = selected {
                    state.retained_routes.remove(&id);
                }
                use landscape_common::flow::failover::WanSwitchCause as Cause;
                let cause = if !config.failover.enable {
                    Cause::ManualPrimary
                } else if reordered {
                    Cause::PriorityChanged
                } else if let Some(previous) = previous {
                    if !has_route(&previous) {
                        Cause::LinkUnavailable
                    } else {
                        match verdict(&previous) {
                            WanLinkHealthState::Healthy => Cause::Recovery,
                            WanLinkHealthState::Unhealthy => Cause::HealthFailure,
                            WanLinkHealthState::Unknown if selected.is_none() => {
                                Cause::UnknownGraceExpired
                            }
                            WanLinkHealthState::Unknown => Cause::HealthUnknown,
                        }
                    }
                } else {
                    Cause::AvailableWan
                };
                let at_ms = now_ms();
                state.status.selected_at_ms = at_ms;
                state.changed = now;
                state.status.history.push(FlowWanSwitchEvent {
                    at_ms,
                    previous,
                    active: selected,
                    reason,
                    connection_policy: policy,
                    cause,
                });
                if state.status.history.len() > 32 {
                    state.status.history.remove(0);
                }
                tracing::info!(
                    flow_id = config.flow_id,
                    ipv6,
                    ?previous,
                    ?selected,
                    ?reason,
                    ?cause,
                    ?policy,
                    "WAN failover exit changed"
                );
            }
            let selected_route = selected.and_then(|id| routes.get(&RouteOwner::Link(id))).cloned();
            if !state.selection_changed && state.selected_route != selected_route {
                // Invalidate before cloning the default-flow alias so owner
                // and Flow 0 publish the new generation in the same update.
                state.generation = state.generation.wrapping_add(1);
                state.retained_routes.clear();
            }
            state.selected = selected;
            state.selected_route = selected_route;
            state.order = order.clone();
            state.status.automatic = config.failover.enable;
            state.status.trigger = config.failover.trigger;
            state.status.active_link_id = selected;
            state.status.active_iface_name = selected
                .and_then(|id| routes.get(&RouteOwner::Link(id)))
                .map(|r| r.info.iface_name.clone());
            state.status.reason = reason;
            state.status.retry_after_secs = retry_after_secs;
            state.status.candidates = order
                .into_iter()
                .map(|id| FlowWanCandidateStatus {
                    link_id: id,
                    iface_name: routes
                        .get(&RouteOwner::Link(id))
                        .map(|r| r.info.iface_name.clone()),
                    route_available: has_route(&id),
                    health: probe_verdict(&id),
                })
                .collect();
            let targets = selected
                .and_then(|id| routes.get(&RouteOwner::Link(id)))
                .map(|route| vec![(route.clone(), 1)])
                .unwrap_or_default();
            result.insert(config.flow_id, targets);
        }
        result
    }

    pub(super) fn remove(&mut self, flow_id: FlowId) {
        self.active.remove(&(flow_id, false));
        self.active.remove(&(flow_id, true));
        self.published.remove(&(flow_id, false));
        self.published.remove(&(flow_id, true));
    }

    fn changed_targets(
        &mut self,
        result: HashMap<FlowId, Vec<(WanRouteTarget, u32)>>,
        ipv6: bool,
    ) -> HashMap<FlowId, Vec<(WanRouteTarget, u32)>> {
        result
            .into_iter()
            .filter(|(id, targets)| {
                let key = (*id, ipv6);
                if self.published.get(&key) == Some(targets) {
                    return false;
                }
                self.published.insert(key, targets.clone());
                true
            })
            .collect()
    }
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
    /// Resolve a DNS upstream's opt-in flow binding without consulting the
    /// kernel default route. Each family may independently have no usable WAN.
    pub async fn dns_wan_binding(
        &self,
        flow_id: u32,
    ) -> landscape_common::dns::bind::DnsWanBinding {
        let selections = self.failover_selections.lock().await;
        let ipv4_routes = self.clone_ipv4_wan_infos().await;
        let ipv6_routes = self.clone_ipv6_wan_infos().await;
        let get = |ipv6, routes: &WanRoutesByOwner| {
            let route = if flow_id == 0 && selections.default_owner.is_none() {
                routes.values().find(|r| r.info.default_route)
            } else {
                let targets = selections.published.get(&(flow_id, ipv6))?;
                let mut effective = targets.iter().filter(|(_, weight)| *weight > 0);
                let (route, _) = effective.next()?;
                effective.all(|(other, _)| other == route).then_some(route)
            }?;
            let link_id = routes.iter().find_map(|(owner, current)| {
                if current != route {
                    return None;
                }
                match owner {
                    RouteOwner::Link(id) => Some(*id),
                    RouteOwner::Netns(_) => None,
                }
            });
            Some((route.info.clone(), link_id))
        };
        let v4 = get(false, &ipv4_routes).and_then(|(r, id)| match r.iface_ip {
            std::net::IpAddr::V4(ip) if !ip.is_unspecified() => Some(((r.iface_name, ip), id)),
            _ => None,
        });
        let v6 = get(true, &ipv6_routes).and_then(|(r, id)| match r.iface_ip {
            std::net::IpAddr::V6(ip) if !ip.is_unspecified() => Some(((r.iface_name, ip), id)),
            _ => None,
        });
        landscape_common::dns::bind::DnsWanBinding {
            ipv4_link_id: v4.as_ref().and_then(|(_, id)| *id),
            ipv6_link_id: v6.as_ref().and_then(|(_, id)| *id),
            ipv4: v4.map(|(address, _)| address),
            ipv6: v6.map(|(address, _)| address),
        }
    }

    pub async fn get_flow_wan_statuses(
        &self,
    ) -> Vec<landscape_common::flow::failover::FlowWanStatus> {
        let selections = self.failover_selections.lock().await;
        let mut statuses: Vec<_> = selections.active.values().map(|s| s.status.clone()).collect();
        let policy = self.router_wan_policy.read().await;
        let applied = self.router_policy_applied.read().await;
        if policy.is_some() {
            let current = applied.as_ref().filter(|s| s.policy == *policy);
            for status in &mut statuses {
                if status.flow_id == 0 || Some(status.flow_id) == selections.default_owner {
                    status.router_policy_applied = Some(current.is_some_and(|s| s.error.is_none()));
                    status.router_policy_error = current.and_then(|s| s.error.clone());
                    status.router_policy_checked_at_ms = current.map(|s| s.checked_at_ms);
                }
            }
        } else if let Some(applied) = applied.as_ref()
            && (applied.policy.is_some() || applied.error.is_some())
        {
            // The owner may have been deleted or changed to weighted mode.
            // Keep cleanup visible on the always-present default-flow card.
            let current = applied.policy.is_none();
            for ipv6 in [false, true] {
                if !statuses.iter().any(|s| s.flow_id == 0 && s.ipv6 == ipv6) {
                    statuses.push(landscape_common::flow::failover::FlowWanStatus {
                        flow_id: 0,
                        ipv6,
                        automatic: false,
                        trigger: Default::default(),
                        active_link_id: None,
                        active_iface_name: None,
                        reason:
                            landscape_common::flow::failover::WanSelectionReason::NoAvailableWan,
                        selected_at_ms: applied.checked_at_ms,
                        retry_after_secs: None,
                        candidates: vec![],
                        history: vec![],
                        router_policy_applied: None,
                        router_policy_error: None,
                        router_policy_checked_at_ms: None,
                        router_policy_cleanup: false,
                    });
                }
            }
            for status in statuses.iter_mut().filter(|s| s.flow_id == 0) {
                status.router_policy_cleanup = true;
                status.router_policy_applied = Some(false);
                status.router_policy_error = current.then(|| applied.error.clone()).flatten();
                status.router_policy_checked_at_ms = current.then_some(applied.checked_at_ms);
            }
        }
        statuses.sort_by_key(|s| (s.flow_id, s.ipv6));
        statuses
    }

    /// Recompute the per-flow WAN target slots for `flow_configs` against the
    /// current WAN route state and sync them into the eBPF maps.
    pub async fn sync_flow_wan_targets(&self, flow_configs: &[FlowConfig]) {
        let mut selections = self.failover_selections.lock().await;
        let health = self.clone_link_healths().await;
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let mut ipv4_result = selections.resolve(flow_configs, &ipv4_wan_infos, &health, false);

        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        let health_v6 = self.get_link_healths_for_family(true).await;
        let mut ipv6_result = selections.resolve(flow_configs, &ipv6_wan_infos, &health_v6, true);

        let default = flow_configs
            .iter()
            .find(|c| c.enable && c.failover.bind_default_flow && c.failover.ordered_targets());
        let owner_changed = selections.default_owner != default.map(|c| c.flow_id);
        let was_default = selections.default_owner.is_some();
        selections.default_owner = default.map(|c| c.flow_id);
        for (ipv6, result, routes) in
            [(false, &mut ipv4_result, &ipv4_wan_infos), (true, &mut ipv6_result, &ipv6_wan_infos)]
        {
            if let Some(config) = default {
                result.insert(0, result.get(&config.flow_id).cloned().unwrap_or_default());
                if let Some(mut alias) = selections.active.get(&(config.flow_id, ipv6)).cloned() {
                    let source_changed =
                        selections.default_source_generation.get(&ipv6) != Some(&alias.generation);
                    selections.default_source_generation.insert(ipv6, alias.generation);
                    let old_generation = selections
                        .active
                        .get(&(0, ipv6))
                        .map_or(alias.generation, |s| s.generation);
                    alias.generation =
                        old_generation.wrapping_add(u64::from(owner_changed || source_changed));
                    alias.status.flow_id = 0;
                    selections.active.insert((0, ipv6), alias);
                }
            } else if was_default {
                result.insert(
                    0,
                    routes
                        .values()
                        .find(|r| r.info.default_route)
                        .cloned()
                        .map(|r| vec![(r, 1)])
                        .unwrap_or_default(),
                );
                selections.active.remove(&(0, ipv6));
                self.dataplane.set_connection_generation(0, ipv6, None);
            }
        }
        let router_policy = default.filter(|c| c.failover.bind_router_traffic).map(|_| {
            landscape_common::sys_service::route_service::RouterWanPolicy {
                ipv4: ipv4_result.get(&0).and_then(|r| r.first()).map(|(r, _)| r.info.clone()),
                ipv6: ipv6_result.get(&0).and_then(|r| r.first()).map(|(r, _)| r.info.clone()),
            }
        });
        {
            let mut current = self.router_wan_policy.write().await;
            if *current != router_policy {
                *current = router_policy;
                self.kernel_default_notify.notify_one();
            }
        }
        let ipv4_updates = selections.changed_targets(ipv4_result.clone(), false);
        let ipv6_updates = selections.changed_targets(ipv6_result.clone(), true);
        let changed = !ipv4_updates.is_empty() || !ipv6_updates.is_empty();
        if changed {
            warn_fully_unresolved_flows(flow_configs, &ipv4_result, &ipv6_result);
        }
        apply_ipv4_target_refresh_result(&*self.dataplane, ipv4_updates);
        apply_ipv6_target_refresh_result(&*self.dataplane, ipv6_updates);

        for config in flow_configs {
            for ipv6 in [false, true] {
                let generation =
                    selections.active.get(&(config.flow_id, ipv6)).map(|s| s.generation);
                self.dataplane.set_connection_generation(config.flow_id, ipv6, generation);
            }
        }
        if default.is_some() {
            for ipv6 in [false, true] {
                self.dataplane.set_connection_generation(
                    0,
                    ipv6,
                    selections.active.get(&(0, ipv6)).map(|s| s.generation),
                );
            }
        }
        if changed {
            self.dataplane.invalidate_lan_cache();
        }
    }

    /// Drop all WAN target slots of `flow_id` (e.g. after the flow config is
    /// deleted).
    pub async fn clear_flow_wan_targets(&self, flow_id: FlowId) {
        let mut selections = self.failover_selections.lock().await;
        let clear_default = selections.default_owner == Some(flow_id);
        if clear_default {
            selections.default_owner = None;
            selections.remove(0);
            self.dataplane.set_connection_generation(0, false, None);
            self.dataplane.set_connection_generation(0, true, None);
            // Flow 0 slots mirror the deleted default binding; without this
            // they would keep routing default traffic over the removed policy.
            self.dataplane.del_wan_slots_v4(0);
            self.dataplane.del_wan_slots_v6(0);
            *self.router_wan_policy.write().await = None;
            self.kernel_default_notify.notify_one();
        }
        selections.remove(flow_id);
        self.dataplane.set_connection_generation(flow_id, false, None);
        self.dataplane.set_connection_generation(flow_id, true, None);
        self.dataplane.del_wan_slots_v4(flow_id);
        self.dataplane.del_wan_slots_v6(flow_id);
        self.dataplane.invalidate_lan_cache();
        drop(selections);
        if clear_default {
            self.refresh_default_router().await;
        }
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    use landscape_common::flow::{FlowFailoverConfig, FlowTargetMode, WeightedFlowTarget};
    use landscape_common::sys_service::route_service::RouteTargetInfo;
    use landscape_common::wan_link::HealthEvaluator;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn default_alias_tracks_sticky_selection_and_clears_on_disable() {
        let (mut config, mut routes, health, primary, backup) = setup();
        config.failover.bind_default_flow = true;
        config.failover.bind_router_traffic = true;
        config.failover.auto_failback = false;
        routes.get_mut(&RouteOwner::Link(primary)).unwrap().info.default_route = true;
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route).await;
        }
        for (_, mut state) in health {
            if state.link_id == primary {
                state.state = WanLinkHealthState::Unhealthy;
            }
            service.update_link_health(state).await;
        }
        service.sync_flow_wan_targets(&[config.clone()]).await;
        let status = service.get_flow_wan_statuses().await;
        assert!(status.iter().filter(|s| !s.ipv6).all(|s| s.active_link_id == Some(backup)));
        assert_eq!(service.dns_wan_binding(0).await.ipv4.unwrap().0, "wan2");
        assert_eq!(service.dns_wan_binding(0).await.ipv4_link_id, Some(backup));
        let mut restored = HealthEvaluator::new(primary, 1, 1, 1).info().clone();
        restored.state = WanLinkHealthState::Healthy;
        service.update_link_health(restored).await;
        service.refresh_default_router().await;
        service.sync_flow_wan_targets(&[config.clone()]).await;
        assert_eq!(
            service.dns_wan_binding(0).await.ipv4.unwrap().0,
            "wan2",
            "route refresh cannot override sticky default policy"
        );
        config.failover.enable = false;
        service.sync_flow_wan_targets(&[config.clone()]).await;
        assert_eq!(
            service.dns_wan_binding(0).await.ipv4.unwrap().0,
            "wan1",
            "manual mode takes precedence"
        );
        assert_eq!(service.dns_wan_binding(0).await.ipv4_link_id, Some(primary));
        config.failover.bind_default_flow = false;
        config.failover.bind_router_traffic = false;
        service.sync_flow_wan_targets(&[config]).await;
        assert!(service.get_flow_wan_statuses().await.iter().all(|s| s.flow_id != 0));
        assert!(service.router_wan_policy.read().await.is_none());
        assert_eq!(service.dns_wan_binding(0).await.ipv4_link_id, Some(primary));
    }

    #[tokio::test]
    async fn router_policy_status_distinguishes_pending_failure_and_applied() {
        let (mut config, routes, health, _, _) = setup();
        config.failover.bind_default_flow = true;
        config.failover.bind_router_traffic = true;
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route).await;
        }
        for (_, state) in health {
            service.update_link_health(state).await;
        }
        service.sync_flow_wan_targets(&[config.clone()]).await;
        let pending = service.get_flow_wan_statuses().await;
        assert!(!pending.is_empty());
        assert!(pending.iter().all(|s| s.router_policy_applied == Some(false)
            && s.router_policy_error.is_none()
            && s.router_policy_checked_at_ms.is_none()));
        let policy = service.router_wan_policy.read().await.clone();
        *service.router_policy_applied.write().await = Some(super::super::RouterPolicyApplyState {
            policy,
            error: Some("rule priority 10427 occupied".into()),
            checked_at_ms: 123,
        });
        let failed = service.get_flow_wan_statuses().await;
        assert!(failed.iter().all(|s| s.router_policy_applied == Some(false)
            && s.router_policy_error.as_deref() == Some("rule priority 10427 occupied")
            && s.router_policy_checked_at_ms == Some(123)));
        service.reconcile_router_wan_policy().await;
        assert!(
            service
                .get_flow_wan_statuses()
                .await
                .iter()
                .all(|s| s.router_policy_applied == Some(true) && s.router_policy_error.is_none())
        );
        config.failover.bind_router_traffic = false;
        service.sync_flow_wan_targets(&[config]).await;
        let cleanup = service.get_flow_wan_statuses().await;
        assert!(cleanup.iter().filter(|s| s.flow_id == 0).all(|s| s.router_policy_cleanup
            && s.router_policy_applied == Some(false)
            && s.router_policy_error.is_none()));
        *service.router_policy_applied.write().await = Some(super::super::RouterPolicyApplyState {
            policy: None,
            error: Some("-6: cannot remove old policy".into()),
            checked_at_ms: 456,
        });
        service.clear_flow_wan_targets(9).await;
        service.sync_flow_wan_targets(&[]).await;
        let failed_cleanup = service.get_flow_wan_statuses().await;
        assert_eq!(failed_cleanup.len(), 2, "deleted owner must not hide failed cleanup");
        assert!(failed_cleanup.iter().all(|s| s.flow_id == 0
            && s.router_policy_cleanup
            && s.router_policy_error.as_deref() == Some("-6: cannot remove old policy")
            && s.router_policy_checked_at_ms == Some(456)));
        service.reconcile_router_wan_policy().await;
        assert!(service.get_flow_wan_statuses().await.is_empty());
    }

    #[test]
    fn retained_backup_failure_honors_policy_and_route_changes_in_both_families() {
        use landscape_common::flow::FlowConnectionPolicy;
        for ipv6 in [false, true] {
            for policy in
                [FlowConnectionPolicy::ResetExisting, FlowConnectionPolicy::NewConnectionsOnly]
            {
                for disruption in ["health", "removed", "changed"] {
                    let (mut config, mut routes, mut health, primary, backup) = setup();
                    config.failover.failure_connection_policy = policy;
                    let mut state = FailoverSelections::default();
                    let now = std::time::Instant::now();
                    let resolve = |state: &mut FailoverSelections,
                                   routes: &WanRoutesByOwner,
                                   health: &LinkHealths,
                                   secs| {
                        state.resolve_at(
                            std::slice::from_ref(&config),
                            routes,
                            health,
                            ipv6,
                            now + std::time::Duration::from_secs(secs),
                        );
                    };
                    resolve(&mut state, &routes, &health, 0);
                    health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
                    resolve(&mut state, &routes, &health, 1);
                    health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
                    resolve(&mut state, &routes, &health, 2);
                    let generation = state.active[&(9, ipv6)].generation;
                    assert!(state.active[&(9, ipv6)].retained_routes.contains_key(&backup));
                    match disruption {
                        "health" => {
                            health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy
                        }
                        "removed" => {
                            routes.remove(&RouteOwner::Link(backup));
                        }
                        _ => routes.get_mut(&RouteOwner::Link(backup)).unwrap().info.ifindex += 10,
                    }
                    resolve(&mut state, &routes, &health, 3);
                    let after = &state.active[&(9, ipv6)];
                    assert_eq!(after.selected, Some(primary));
                    let reset =
                        policy == FlowConnectionPolicy::ResetExisting || disruption == "changed";
                    assert_eq!(
                        after.generation != generation,
                        reset,
                        "{ipv6} {policy:?} {disruption}"
                    );
                    let final_generation = after.generation;
                    resolve(&mut state, &routes, &health, 4);
                    assert_eq!(
                        state.active[&(9, ipv6)].generation,
                        final_generation,
                        "one reset per event"
                    );
                }
            }
        }
    }

    #[test]
    fn retained_unknown_respects_grace_fail_open_and_explicit_keep_policy() {
        use landscape_common::flow::FlowConnectionPolicy;
        for fail_open in [false, true] {
            for policy in
                [FlowConnectionPolicy::ResetExisting, FlowConnectionPolicy::NewConnectionsOnly]
            {
                let (mut config, routes, mut health, primary, backup) = setup();
                config.failover.unknown_grace_secs = 5;
                config.failover.fail_open_on_unknown = fail_open;
                config.failover.failure_connection_policy = policy;
                let mut state = FailoverSelections::default();
                let now = std::time::Instant::now();
                let resolve = |state: &mut FailoverSelections, health: &LinkHealths, secs| {
                    state.resolve_at(
                        std::slice::from_ref(&config),
                        &routes,
                        health,
                        false,
                        now + std::time::Duration::from_secs(secs),
                    );
                    state.active[&(9, false)].generation
                };
                resolve(&mut state, &health, 0);
                health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
                resolve(&mut state, &health, 1);
                health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
                let generation = resolve(&mut state, &health, 2);
                health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unknown;
                assert_eq!(resolve(&mut state, &health, 3), generation);
                assert_eq!(resolve(&mut state, &health, 7), generation);
                let reset = policy == FlowConnectionPolicy::ResetExisting && !fail_open;
                assert_eq!(resolve(&mut state, &health, 8) != generation, reset);
                assert_eq!(state.active[&(9, false)].selected, Some(primary));
            }
        }
    }

    #[test]
    fn unused_backup_failure_does_not_reset_active_connections() {
        let (config, routes, mut health, _, backup) = setup();
        let mut state = FailoverSelections::default();
        selected(&mut state, &config, &routes, &health);
        let generation = state.active[&(9, false)].generation;
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        selected(&mut state, &config, &routes, &health);
        assert_eq!(state.active[&(9, false)].generation, generation);
    }

    #[test]
    fn kept_connection_to_removed_wan_is_invalidated_on_changed_reappearance() {
        let (mut config, mut routes, mut health, primary, _) = setup();
        config.failover.failure_connection_policy =
            landscape_common::flow::FlowConnectionPolicy::NewConnectionsOnly;
        let mut state = FailoverSelections::default();
        selected(&mut state, &config, &routes, &health);
        let mut original = routes.remove(&RouteOwner::Link(primary)).unwrap();
        selected(&mut state, &config, &routes, &health);
        assert!(state.active[&(9, false)].retained_routes.contains_key(&primary));
        let generation = state.active[&(9, false)].generation;
        original.info.ifindex += 10;
        routes.insert(RouteOwner::Link(primary), original);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        selected(&mut state, &config, &routes, &health);
        assert_ne!(state.active[&(9, false)].generation, generation);
    }

    #[tokio::test]
    async fn retained_backup_failure_resets_default_alias_without_changing_active_exit() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.bind_default_flow = true;
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route).await;
        }
        for info in health.values() {
            service.update_link_health(info.clone()).await;
        }
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        for verdict in [WanLinkHealthState::Unhealthy, WanLinkHealthState::Healthy] {
            health.get_mut(&primary).unwrap().state = verdict;
            service.update_link_health(health[&primary].clone()).await;
            service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        }
        let generations = {
            let state = service.failover_selections.lock().await;
            (
                state.active[&(9, false)].generation,
                state.active[&(0, false)].generation,
                state.active[&(0, true)].generation,
            )
        };
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        service.update_link_health(health[&backup].clone()).await;
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        let state = service.failover_selections.lock().await;
        assert_eq!(state.active[&(9, false)].selected, Some(primary));
        assert_eq!(state.active[&(0, false)].selected, Some(primary));
        assert_ne!(state.active[&(9, false)].generation, generations.0);
        assert_ne!(state.active[&(0, false)].generation, generations.1);
        assert_eq!(state.active[&(0, true)].generation, generations.2);
    }

    #[tokio::test]
    async fn selected_route_change_invalidates_owner_and_default_alias_once() {
        let (mut config, routes, health, primary, _) = setup();
        config.failover.bind_default_flow = true;
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route).await;
        }
        for info in health.into_values() {
            service.update_link_health(info).await;
        }
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        let generations = {
            let state = service.failover_selections.lock().await;
            (state.active[&(9, false)].generation, state.active[&(0, false)].generation)
        };
        let mut route = service.clone_ipv4_wan_infos().await[&RouteOwner::Link(primary)].clone();
        route.info.ifindex += 10;
        service.insert_ipv4_wan_route(&RouteOwner::Link(primary), route).await;
        for _ in 0..2 {
            service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
            let state = service.failover_selections.lock().await;
            assert_eq!(state.active[&(9, false)].generation, generations.0 + 1);
            assert_eq!(state.active[&(0, false)].generation, generations.1 + 1);
        }
    }

    #[tokio::test]
    async fn weighted_dns_binding_uses_only_distinct_positive_weight_targets() {
        let (mut config, routes, _, primary, _) = setup();
        config.failover = Default::default();
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route).await;
        }
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        assert!(service.dns_wan_binding(9).await.ipv4.is_none());
        config.flow_targets[1].weight = 0;
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        assert_eq!(service.dns_wan_binding(9).await.ipv4_link_id, Some(primary));
        config.flow_targets.push(config.flow_targets[0].clone());
        service.sync_flow_wan_targets(std::slice::from_ref(&config)).await;
        assert_eq!(service.dns_wan_binding(9).await.ipv4_link_id, Some(primary));
    }

    fn setup() -> (FlowConfig, WanRoutesByOwner, LinkHealths, Uuid, Uuid) {
        let primary = Uuid::from_u128(1);
        let backup = Uuid::from_u128(2);
        let mut routes = WanRoutesByOwner::new();
        let mut health = LinkHealths::new();
        for (id, name, index) in [(primary, "wan1", 1), (backup, "wan2", 2)] {
            routes.insert(
                RouteOwner::Link(id),
                WanRouteTarget::link(
                    index as u16,
                    RouteTargetInfo::new_gateway_v4(
                        index,
                        name,
                        None,
                        Ipv4Addr::new(192, 0, 2, index as u8),
                        Ipv4Addr::new(192, 0, 2, 254),
                        false,
                    ),
                ),
            );
            let mut info = HealthEvaluator::new(id, 3, 3, 1).info().clone();
            info.state = WanLinkHealthState::Healthy;
            health.insert(id, info);
        }
        let config = FlowConfig {
            id: Uuid::nil(),
            enable: true,
            flow_id: 9,
            flow_match_rules: vec![],
            flow_targets: [primary, backup]
                .into_iter()
                .map(|link_id| {
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { link_id, name: String::new() },
                        7,
                    )
                })
                .collect(),
            failover: FlowFailoverConfig {
                mode: FlowTargetMode::PrimaryBackup,
                enable: true,
                auto_failback: true,
                unknown_grace_secs: 0,
                failback_delay_secs: 0,
                switch_hold_secs: 0,
                ..Default::default()
            },
            name: String::new(),
            remark: String::new(),
            update_at: 0.0,
        };
        (config, routes, health, primary, backup)
    }

    fn selected(
        state: &mut FailoverSelections,
        config: &FlowConfig,
        routes: &WanRoutesByOwner,
        health: &LinkHealths,
    ) -> Vec<String> {
        state.resolve(std::slice::from_ref(config), routes, health, false)[&9]
            .iter()
            .map(|(target, _)| target.info.iface_name.clone())
            .collect()
    }

    #[tokio::test]
    async fn link_state_default_alias_and_dns_follow_route_loss_without_health() {
        use landscape_common::flow::FlowFailoverTrigger;
        let (mut cfg, routes, _, a, b) = setup();
        cfg.failover.trigger = FlowFailoverTrigger::LinkState;
        cfg.failover.bind_default_flow = true;
        let service = super::super::test_used_ip_route();
        for (owner, route) in routes {
            service.insert_ipv4_wan_route(&owner, route.clone()).await;
            let mut v6 = route;
            v6.info.iface_ip = "2001:db8::2".parse().unwrap();
            v6.info.gateway_ip = "2001:db8::1".parse().unwrap();
            service.insert_ipv6_wan_route(&owner, v6).await;
        }
        service.sync_flow_wan_targets(std::slice::from_ref(&cfg)).await;
        let statuses = service.get_flow_wan_statuses().await;
        assert_eq!(statuses.len(), 4);
        assert!(statuses.iter().all(|s| s.active_link_id == Some(a) && s.trigger == FlowFailoverTrigger::LinkState));
        service.remove_ipv4_link_route(a).await;
        service.remove_ipv6_link_route(a).await;
        service.sync_flow_wan_targets(&[cfg]).await;
        assert!(service.get_flow_wan_statuses().await.iter().all(|s| s.active_link_id == Some(b)));
        let dns = service.dns_wan_binding(0).await;
        assert_eq!(dns.ipv4_link_id, Some(b));
        assert_eq!(dns.ipv6_link_id, Some(b));
    }

    #[test]
    fn link_state_ignores_probes_but_fails_over_and_waits_for_session_recovery() {
        use landscape_common::flow::FlowFailoverTrigger;
        for ipv6 in [false, true] {
            let (mut cfg, mut routes, mut health, a, b) = setup();
            cfg.failover.trigger = FlowFailoverTrigger::LinkState;
            cfg.failover.failback_delay_secs = 5;
            cfg.failover.bind_default_flow = true;
            let mut state = FailoverSelections::default();
            let now = std::time::Instant::now();
            let choose = |state: &mut FailoverSelections,
                          cfg: &FlowConfig,
                          routes: &WanRoutesByOwner,
                          health: &LinkHealths,
                          secs| {
                state.resolve_at(
                    std::slice::from_ref(cfg),
                    routes,
                    health,
                    ipv6,
                    now + std::time::Duration::from_secs(secs),
                );
                state.active[&(9, ipv6)].selected
            };
            for h in health.values_mut() {
                h.state = WanLinkHealthState::Unhealthy;
            }
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 0), Some(a));
            let generation = state.active[&(9, ipv6)].generation;
            assert_eq!(
                state.active[&(9, ipv6)].status.candidates[0].health,
                WanLinkHealthState::Unhealthy
            );
            health.clear();
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 1000), Some(a));
            assert_eq!(state.active[&(9, ipv6)].generation, generation);
            let primary = routes.remove(&RouteOwner::Link(a)).unwrap();
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 1001), Some(b));
            assert_eq!(
                state.active[&(9, ipv6)].status.history.last().unwrap().cause,
                landscape_common::flow::failover::WanSwitchCause::LinkUnavailable
            );
            routes.insert(RouteOwner::Link(a), primary);
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 1002), Some(b));
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 1006), Some(b));
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 1007), Some(a));
            let retained_generation = state.active[&(9, ipv6)].generation;
            let mut failed = HealthEvaluator::new(b, 1, 1, 1).info().clone();
            failed.state = WanLinkHealthState::Unhealthy;
            health.insert(b, failed);
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 2000), Some(a));
            assert_eq!(state.active[&(9, ipv6)].generation, retained_generation);
            routes.remove(&RouteOwner::Link(b));
            choose(&mut state, &cfg, &routes, &health, 2001);
            assert!(state.active[&(9, ipv6)].generation > retained_generation);
            routes.clear();
            cfg.failover.fail_open_on_unknown = true;
            assert_eq!(choose(&mut state, &cfg, &routes, &health, 2002), None);
        }
    }

    #[test]
    fn fails_over_on_probe_failure_and_returns_after_recovery() {
        let (config, routes, mut health, primary, _) = setup();
        let mut state = FailoverSelections::default();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        assert_eq!(
            state.active[&(9, false)].status.history.last().unwrap().cause,
            landscape_common::flow::failover::WanSwitchCause::HealthFailure
        );
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        assert_eq!(
            state.active[&(9, false)].status.history.last().unwrap().cause,
            landscape_common::flow::failover::WanSwitchCause::Recovery
        );
    }

    #[test]
    fn missing_route_overrides_stale_healthy_verdict() {
        let (config, mut routes, health, primary, _) = setup();
        routes.remove(&RouteOwner::Link(primary));
        assert_eq!(
            selected(&mut FailoverSelections::default(), &config, &routes, &health),
            ["wan2"]
        );
    }

    #[test]
    fn unknown_or_both_failed_never_falls_back_to_an_unrelated_wan() {
        let (config, routes, mut health, primary, backup) = setup();
        let mut state = FailoverSelections::default();
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unknown;
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert!(selected(&mut state, &config, &routes, &health).is_empty());
        health.clear();
        assert!(selected(&mut state, &config, &routes, &health).is_empty());
    }

    #[test]
    fn sticky_backup_survives_recovery_but_order_changes_apply() {
        let (mut config, routes, mut health, primary, backup) = setup();
        let mut state = FailoverSelections::default();
        config.failover.auto_failback = false;
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Healthy;
        config.flow_targets.reverse();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
    }

    #[test]
    fn legacy_weighted_mode_and_disabled_flow_remain_unchanged() {
        let (mut config, routes, _, _, _) = setup();
        let mut state = FailoverSelections::default();
        config.failover.enable = false;
        config.failover.mode = FlowTargetMode::Weighted;
        let result = state.resolve(&[config.clone()], &routes, &LinkHealths::new(), false);
        assert_eq!(result[&9].len(), 2);
        assert!(result[&9].iter().all(|(_, weight)| *weight == 7));
        config.enable = false;
        assert!(selected(&mut state, &config, &routes, &LinkHealths::new()).is_empty());
    }

    #[test]
    fn automatic_switching_off_stays_on_primary_even_when_unhealthy() {
        let (mut config, mut routes, mut health, primary, _) = setup();
        let mut state = FailoverSelections::default();
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan2"]);
        config.failover.enable = false;
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        routes.remove(&RouteOwner::Link(primary));
        assert!(
            selected(&mut state, &config, &routes, &health).is_empty(),
            "must not use backup while automatic switching is off"
        );
    }

    #[test]
    fn unknown_grace_expires_and_fail_open_never_revives_known_failure() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.unknown_grace_secs = 30;
        health.clear();
        let mut state = FailoverSelections::default();
        let now = std::time::Instant::now();
        let resolve =
            |state: &mut FailoverSelections, cfg: &FlowConfig, health: &LinkHealths, secs| {
                state.resolve_at(
                    std::slice::from_ref(cfg),
                    &routes,
                    health,
                    false,
                    now + std::time::Duration::from_secs(secs),
                )[&9]
                    .clone()
            };
        assert_eq!(resolve(&mut state, &config, &health, 0)[0].0.info.iface_name, "wan1");
        assert_eq!(state.active[&(9, false)].status.retry_after_secs, Some(30));
        assert!(resolve(&mut state, &config, &health, 30).is_empty());
        config.failover.fail_open_on_unknown = true;
        assert_eq!(resolve(&mut state, &config, &health, 31)[0].0.info.iface_name, "wan1");
        let mut failed = HealthEvaluator::new(primary, 1, 1, 1).info().clone();
        failed.state = WanLinkHealthState::Unhealthy;
        health.insert(primary, failed.clone());
        assert_eq!(resolve(&mut state, &config, &health, 32)[0].0.info.iface_name, "wan2");
        failed.link_id = backup;
        health.insert(backup, failed);
        assert!(resolve(&mut state, &config, &health, 33).is_empty());
    }

    #[test]
    fn healthy_backup_wins_over_unknown_primary_even_during_grace() {
        let (mut config, routes, mut health, primary, _) = setup();
        config.failover.unknown_grace_secs = 60;
        config.failover.fail_open_on_unknown = true;
        health.remove(&primary);
        assert_eq!(
            selected(&mut FailoverSelections::default(), &config, &routes, &health),
            ["wan2"]
        );
    }

    #[test]
    fn fresh_unknown_backup_is_used_after_primary_grace_expires() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.unknown_grace_secs = 30;
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unknown;
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        let mut state = FailoverSelections::default();
        let now = std::time::Instant::now();
        let resolve = |state: &mut FailoverSelections, health: &LinkHealths, secs| {
            state.resolve_at(
                std::slice::from_ref(&config),
                &routes,
                health,
                false,
                now + std::time::Duration::from_secs(secs),
            )[&9]
                .clone()
        };
        assert_eq!(resolve(&mut state, &health, 0)[0].0.info.iface_name, "wan1");
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unknown;
        assert_eq!(resolve(&mut state, &health, 31)[0].0.info.iface_name, "wan2");
        assert_eq!(state.active[&(9, false)].status.retry_after_secs, Some(30));
        assert_eq!(resolve(&mut state, &health, 60)[0].0.info.iface_name, "wan2");
        assert!(resolve(&mut state, &health, 61).is_empty());
    }

    #[test]
    fn failback_requires_continuous_health_but_emergency_failure_is_immediate() {
        let (mut config, routes, mut health, primary, backup) = setup();
        config.failover.failback_delay_secs = 30;
        let mut state = FailoverSelections::default();
        let now = std::time::Instant::now();
        let resolve = |state: &mut FailoverSelections, health: &LinkHealths, secs| {
            state.resolve_at(
                std::slice::from_ref(&config),
                &routes,
                health,
                false,
                now + std::time::Duration::from_secs(secs),
            )[&9][0]
                .0
                .info
                .iface_name
                .clone()
        };
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 0), "wan2");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(resolve(&mut state, &health, 1), "wan2");
        assert_eq!(resolve(&mut state, &health, 30), "wan2");
        assert_eq!(resolve(&mut state, &health, 31), "wan1");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 32), "wan2");
        health.get_mut(&primary).unwrap().state = WanLinkHealthState::Healthy;
        assert_eq!(resolve(&mut state, &health, 33), "wan2");
        health.get_mut(&backup).unwrap().state = WanLinkHealthState::Unhealthy;
        assert_eq!(resolve(&mut state, &health, 34), "wan1");
        assert_eq!(state.active[&(9, false)].status.history.len(), 4);
    }

    #[test]
    fn address_families_select_only_routes_in_their_own_table() {
        let (config, routes, health, _, _) = setup();
        let mut state = FailoverSelections::default();
        assert_eq!(selected(&mut state, &config, &routes, &health), ["wan1"]);
        let empty = state.resolve(&[config], &WanRoutesByOwner::new(), &health, true);
        assert!(empty[&9].is_empty());
    }
}
