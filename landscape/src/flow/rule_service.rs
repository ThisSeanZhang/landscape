use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::error::DbError,
    database::store::{Change, ConfigStore},
    event::dns::DnsEvent,
    event::hub::EnrolledDeviceEventReader,
    flow::{FlowEntryMatchMode, FlowRuleError, config::FlowConfig, dataplane::FlowRuleDataplane},
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
    wan_link::WanLinkHealthState,
};
use landscape_database::{
    flow_rule::repository::{FlowConfigRepository, find_duplicate_resolved_modes},
    provider::LandscapeDBServiceProvider,
};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

#[derive(Clone)]
pub struct FlowRuleService {
    store: FlowConfigRepository,
    dns_events_tx: mpsc::Sender<DnsEvent>,
    route_service: IpRouteService,
    dataplane: Arc<dyn FlowRuleDataplane>,
}

impl FlowRuleService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        dns_events_tx: mpsc::Sender<DnsEvent>,
        route_service: IpRouteService,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn FlowRuleDataplane>,
    ) -> Self {
        let store = store_provider.flow_rule_store();
        let result = Self { store, dns_events_tx, route_service, dataplane };
        // Subscribe before the initial sync so no WanRouteEvent or
        // WanLinkHealthEvent can slip in between the sync and the
        // subscription; events arriving during the sync only trigger a
        // redundant, idempotent resync.
        let wan_route_events = result.route_service.subscribe_wan_route_events();
        let health_events = result.route_service.subscribe_health_events();
        result.refresh_flow_matches().await;
        result.sync_all_flow_wan_targets().await;

        let this = result.clone();
        spawn_task(task_label::task::FLOW_RULE_OBSERVER, async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_flow_matches().await;
            }
        });

        // Recompute the per-flow WAN target slots whenever the route service
        // reports a WAN route change or an Unhealthy health transition; a
        // single observer serializes both streams against each other.
        let this = result.clone();
        spawn_task(task_label::task::FLOW_WAN_ROUTE_OBSERVER, async move {
            let mut route_events = wan_route_events;
            let mut health_events = health_events;
            let mut route_open = true;
            let mut health_open = true;
            while route_open || health_open {
                let should_sync = tokio::select! {
                    event = route_events.recv(), if route_open => match event {
                        Ok(_) => true,
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            tracing::warn!(
                                "flow wan route observer missed {missed} route events; resyncing"
                            );
                            true
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            route_open = false;
                            false
                        }
                    },
                    event = health_events.recv(), if health_open => match event {
                        Ok(ev) => {
                            ev.from == WanLinkHealthState::Unhealthy
                                || ev.to == WanLinkHealthState::Unhealthy
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            tracing::warn!(
                                "flow wan route observer missed {missed} health events; resyncing"
                            );
                            true
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            health_open = false;
                            false
                        }
                    },
                };
                if should_sync {
                    this.sync_all_flow_wan_targets().await;
                }
            }
        });

        result
    }

    pub async fn refresh_flow_matches(&self) {
        let runtime_configs = match self.store.list_runtime_configs().await {
            Ok(runtime_configs) => runtime_configs,
            Err(error) => {
                tracing::error!("failed to load flow runtime configs: {error:?}");
                return;
            }
        };

        self.dataplane.sync_flow_matches(&runtime_configs);
    }

    /// Recompute every flow's WAN target slots from the current store
    /// contents against the route service's WAN state.
    async fn sync_all_flow_wan_targets(&self) {
        let configs = self.store.list().await.unwrap_or_else(|error| {
            tracing::error!("failed to load flow configs for wan target sync: {error:?}");
            Vec::new()
        });
        self.route_service.sync_flow_wan_targets(&configs).await;
    }

    pub async fn delete_flow_cascade(&self, id: Uuid) -> Result<Option<FlowConfig>, DbError> {
        let old = self.store.delete_flow_with_rules(id).await?;
        if let Some(old) = &old {
            let flow_id = old.flow_id;
            self.notify_deleted(old.clone()).await;
            let _ =
                self.dns_events_tx.send(DnsEvent::RulesChanged { flow_id: Some(flow_id) }).await;
            self.dataplane.set_dst_ip_marks(flow_id, vec![]);
            self.dataplane.invalidate_lan_cache();
        }
        Ok(old)
    }
}

impl FlowRuleService {
    pub async fn find_resolved_conflict_for_modes(
        &self,
        exclude_id: uuid::Uuid,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<(FlowEntryMatchMode, FlowConfig)>, FlowRuleError> {
        self.store.find_resolved_conflict_for_modes(exclude_id, modes).await
    }

    pub async fn find_duplicate_resolved_mode(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<Option<FlowEntryMatchMode>, FlowRuleError> {
        let resolved_modes = self.store.resolve_modes(modes).await?;
        Ok(find_duplicate_resolved_modes(&resolved_modes))
    }

    pub async fn validate_modes_resolvable(
        &self,
        modes: &[FlowEntryMatchMode],
    ) -> Result<(), FlowRuleError> {
        self.store.validate_modes_resolvable(modes).await
    }
}

impl ConfigStoreFlowController for FlowRuleService {}

#[async_trait::async_trait]
impl ConfigStoreController for FlowRuleService {
    type Id = Uuid;
    type Config = FlowConfig;
    type Store = FlowConfigRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        self.refresh_flow_matches().await;
        let configs: Vec<FlowConfig> = changes.into_iter().map(|change| change.new).collect();
        self.route_service.sync_flow_wan_targets(&configs).await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow_matches().await;
        self.route_service.clear_flow_wan_targets(old.flow_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use landscape_common::config::FlowId;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::flow::config::FlowConfig;
    use landscape_common::flow::dataplane::NoopFlowRuleDataplane;
    use landscape_common::flow::{FlowTarget, WeightedFlowTarget};
    use landscape_common::sys_service::route_service::dataplane::RouteTableDataplane;
    use landscape_common::sys_service::route_service::{
        LanRouteInfo, RouteTargetInfo, WanRouteTarget,
    };
    use landscape_common::wan_link::{WanLinkHealthInfo, WanLinkHealthState};
    use landscape_database::provider::LandscapeDBServiceProvider;
    use tokio::sync::{broadcast, mpsc};
    use uuid::Uuid;

    use super::*;

    #[derive(Default)]
    struct RecordingRouteDataplane {
        slots_v4: Mutex<HashMap<FlowId, Vec<(WanRouteTarget, u32)>>>,
        slots_v6: Mutex<HashMap<FlowId, Vec<(WanRouteTarget, u32)>>>,
    }

    impl RecordingRouteDataplane {
        fn target_ifaces_v4(&self, flow_id: FlowId) -> Vec<(String, u32)> {
            self.slots_v4
                .lock()
                .unwrap()
                .get(&flow_id)
                .map(|v| v.iter().map(|(t, w)| (t.info.iface_name.clone(), *w)).collect())
                .unwrap_or_default()
        }

        fn target_ifaces_v6(&self, flow_id: FlowId) -> Vec<(String, u32)> {
            self.slots_v6
                .lock()
                .unwrap()
                .get(&flow_id)
                .map(|v| v.iter().map(|(t, w)| (t.info.iface_name.clone(), *w)).collect())
                .unwrap_or_default()
        }
    }

    #[async_trait::async_trait]
    impl RouteTableDataplane for RecordingRouteDataplane {
        fn add_lan_route(&self, _info: LanRouteInfo) {}
        fn del_lan_route(&self, _info: LanRouteInfo) {}
        fn replace_wan_slots_v4(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]) {
            self.slots_v4.lock().unwrap().insert(flow_id, targets.to_vec());
        }
        fn replace_wan_slots_v6(&self, flow_id: FlowId, targets: &[(WanRouteTarget, u32)]) {
            self.slots_v6.lock().unwrap().insert(flow_id, targets.to_vec());
        }
        fn del_wan_slots_v4(&self, flow_id: FlowId) {
            self.slots_v4.lock().unwrap().remove(&flow_id);
        }
        fn del_wan_slots_v6(&self, flow_id: FlowId) {
            self.slots_v6.lock().unwrap().remove(&flow_id);
        }
        async fn sync_kernel_default_ipv4(&self, _nexthops: &[RouteTargetInfo]) -> bool {
            true
        }
        async fn sync_kernel_default_ipv6(&self, _nexthops: &[RouteTargetInfo]) -> bool {
            true
        }
        fn invalidate_lan_cache(&self) {}
    }

    fn health(link_id: Uuid, state: WanLinkHealthState) -> WanLinkHealthInfo {
        WanLinkHealthInfo {
            link_id,
            state,
            consecutive_failures: if state == WanLinkHealthState::Unhealthy { 4 } else { 0 },
            targets: Vec::new(),
            rtt_ewma_ms: None,
            loss_ewma: None,
            last_success_at: None,
            last_failure_at: None,
            updated_at: 0.0,
        }
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not satisfied in time");
    }

    #[tokio::test]
    async fn health_events_drive_zero_redial_ecmp_failover_and_isolated_fail_open() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let dataplane = Arc::new(RecordingRouteDataplane::default());
        let route_service = IpRouteService::new(dataplane.clone());

        let wan1_id = Uuid::new_v4();
        let wan2_id = Uuid::new_v4();

        // Persist Flow 2 (ECMP 2:3), Flow 4 (WAN2 isolated), Flow 5 (ECMP 2:3).
        let flow_store = provider.flow_rule_store();
        for (flow_id, targets) in [
            (
                2u32,
                vec![
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { name: "wan1".to_string(), link_id: wan1_id },
                        2,
                    ),
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { name: "wan2".to_string(), link_id: wan2_id },
                        3,
                    ),
                ],
            ),
            (
                4u32,
                vec![WeightedFlowTarget::new(
                    FlowTarget::Interface { name: "wan2".to_string(), link_id: wan2_id },
                    1,
                )],
            ),
            (
                5u32,
                vec![
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { name: "wan1".to_string(), link_id: wan1_id },
                        2,
                    ),
                    WeightedFlowTarget::new(
                        FlowTarget::Interface { name: "wan2".to_string(), link_id: wan2_id },
                        3,
                    ),
                ],
            ),
        ] {
            flow_store
                .upsert(FlowConfig {
                    id: Uuid::new_v4(),
                    enable: true,
                    flow_id,
                    flow_match_rules: Vec::new(),
                    flow_targets: targets,
                    balance_mode: Default::default(),
                    name: format!("flow-{flow_id}"),
                    remark: String::new(),
                    update_at: 0.0,
                })
                .await
                .unwrap();
        }

        let (dns_tx, _dns_rx) = mpsc::channel(8);
        let (_dev_tx, dev_rx) = broadcast::channel(8);
        let _flow_service = FlowRuleService::new(
            provider,
            dns_tx,
            route_service.clone(),
            EnrolledDeviceEventReader::new(dev_rx),
            Arc::new(NoopFlowRuleDataplane),
        )
        .await;

        // Bring up IPv4 + IPv6 routes on both WANs.
        route_service
            .insert_ipv4_link_route(
                wan1_id,
                WanRouteTarget::link(
                    2,
                    RouteTargetInfo::new_gateway_v4(
                        10,
                        "wan1",
                        None,
                        Ipv4Addr::new(198, 51, 100, 10),
                        Ipv4Addr::new(198, 51, 100, 1),
                        true,
                    ),
                ),
            )
            .await;
        route_service
            .insert_ipv6_link_route(
                wan1_id,
                WanRouteTarget::link(
                    2,
                    RouteTargetInfo::new_gateway_v6(
                        10,
                        "wan1",
                        None,
                        Ipv6Addr::new(0x240e, 1, 0, 0, 0, 0, 0, 1),
                        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                        true,
                    ),
                ),
            )
            .await;
        route_service
            .insert_ipv4_link_route(
                wan2_id,
                WanRouteTarget::link(
                    3,
                    RouteTargetInfo::new_gateway_v4(
                        11,
                        "wan2",
                        None,
                        Ipv4Addr::new(203, 0, 113, 10),
                        Ipv4Addr::new(203, 0, 113, 1),
                        false,
                    ),
                ),
            )
            .await;
        route_service
            .insert_ipv6_link_route(
                wan2_id,
                WanRouteTarget::link(
                    3,
                    RouteTargetInfo::new_gateway_v6(
                        11,
                        "wan2",
                        None,
                        Ipv6Addr::new(0x2409, 2, 0, 0, 0, 0, 0, 1),
                        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                        false,
                    ),
                ),
            )
            .await;

        let dual = vec![("wan1".to_string(), 2), ("wan2".to_string(), 3)];
        let only_wan2_ecmp = vec![("wan2".to_string(), 3)];
        let only_wan1_ecmp = vec![("wan1".to_string(), 2)];
        let isolated_wan2 = vec![("wan2".to_string(), 1)];

        wait_until(|| {
            dataplane.target_ifaces_v4(5) == dual && dataplane.target_ifaces_v6(5) == dual
        })
        .await;
        assert_eq!(dataplane.target_ifaces_v4(2), dual);
        assert_eq!(dataplane.target_ifaces_v6(2), dual);
        assert_eq!(dataplane.target_ifaces_v4(4), isolated_wan2);
        assert_eq!(dataplane.target_ifaces_v6(4), isolated_wan2);

        // WAN1 flips Unhealthy: Flow 2 and Flow 5 converge both v4 & v6 to WAN2 in 0s.
        route_service.update_link_health(health(wan1_id, WanLinkHealthState::Unhealthy)).await;
        wait_until(|| {
            dataplane.target_ifaces_v4(5) == only_wan2_ecmp
                && dataplane.target_ifaces_v6(5) == only_wan2_ecmp
                && dataplane.target_ifaces_v4(2) == only_wan2_ecmp
                && dataplane.target_ifaces_v6(2) == only_wan2_ecmp
        })
        .await;
        assert_eq!(dataplane.target_ifaces_v4(4), isolated_wan2);
        assert_eq!(dataplane.target_ifaces_v6(4), isolated_wan2);

        // Both WAN1 & WAN2 Unhealthy: Flow 2 & Flow 5 fail-open back to both targets; Flow 4 stays WAN2.
        route_service.update_link_health(health(wan2_id, WanLinkHealthState::Unhealthy)).await;
        wait_until(|| {
            dataplane.target_ifaces_v4(5) == dual && dataplane.target_ifaces_v6(5) == dual
        })
        .await;
        assert_eq!(dataplane.target_ifaces_v4(4), isolated_wan2);
        assert_eq!(dataplane.target_ifaces_v6(4), isolated_wan2);

        // WAN1 recovers Healthy while WAN2 stays Unhealthy: Flow 2 & Flow 5 converge to WAN1,
        // while isolated Flow 4 MUST remain pinned to WAN2 (never leak to WAN1).
        route_service.update_link_health(health(wan1_id, WanLinkHealthState::Healthy)).await;
        wait_until(|| {
            dataplane.target_ifaces_v4(5) == only_wan1_ecmp
                && dataplane.target_ifaces_v6(5) == only_wan1_ecmp
                && dataplane.target_ifaces_v4(2) == only_wan1_ecmp
                && dataplane.target_ifaces_v6(2) == only_wan1_ecmp
        })
        .await;
        assert_eq!(dataplane.target_ifaces_v4(4), isolated_wan2);
        assert_eq!(dataplane.target_ifaces_v6(4), isolated_wan2);

        // WAN2 recovers Healthy: Flow 2 & Flow 5 restore 2:3 dual-stack ECMP.
        route_service.update_link_health(health(wan2_id, WanLinkHealthState::Healthy)).await;
        wait_until(|| {
            dataplane.target_ifaces_v4(5) == dual
                && dataplane.target_ifaces_v6(5) == dual
                && dataplane.target_ifaces_v4(2) == dual
                && dataplane.target_ifaces_v6(2) == dual
        })
        .await;
    }
}
