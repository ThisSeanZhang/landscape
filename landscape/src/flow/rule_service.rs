use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::error::DbError,
    database::store::{Change, ConfigStore},
    event::dns::DnsEvent,
    event::hub::EnrolledDeviceEventReader,
    flow::{FlowEntryMatchMode, FlowRuleError, config::FlowConfig, dataplane::FlowRuleDataplane},
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
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
    target_sync: Arc<tokio::sync::Mutex<()>>,
    dns_bindings: Arc<std::sync::Mutex<Vec<(u32, landscape_common::dns::bind::DnsWanBinding)>>>,
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
        let result = Self {
            store,
            dns_events_tx,
            route_service,
            dataplane,
            target_sync: Default::default(),
            dns_bindings: Default::default(),
        };
        // Subscribe before the initial sync so no WanRouteEvent can slip in
        // between the sync and the subscription; events arriving during the
        // sync only trigger a redundant, idempotent resync.
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
        // reports a WAN route change; the flow side owns the configs, so the
        // join lives here instead of inside the route service.
        let this = result.clone();
        spawn_task(task_label::task::FLOW_WAN_ROUTE_OBSERVER, async move {
            let mut events = wan_route_events;
            let mut health_events = health_events;
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let event = tokio::select! {
                    event = events.recv() => event.map(|_| ()),
                    _ = timer.tick() => Ok(()),
                    event = health_events.recv() => event.map(|_| ()),
                };
                match event {
                    Ok(_) => this.sync_all_flow_wan_targets().await,
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!("flow wan route observer missed {missed} events; resyncing");
                        this.sync_all_flow_wan_targets().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
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
        let _guard = self.target_sync.lock().await;
        let configs = match self.store.list().await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load flow configs for wan target sync: {error:?}");
                return;
            }
        };
        self.route_service.sync_flow_wan_targets(&configs).await;
        let mut bindings = Vec::new();
        for id in std::iter::once(0).chain(configs.iter().map(|c| c.flow_id)) {
            bindings.push((id, self.route_service.dns_wan_binding(id).await));
        }
        bindings.sort_by_key(|(id, _)| *id);
        let changed = {
            let mut old = self.dns_bindings.lock().unwrap_or_else(|e| e.into_inner());
            if *old == bindings {
                false
            } else {
                *old = bindings;
                true
            }
        };
        if changed {
            let _ = self.dns_events_tx.send(DnsEvent::RulesChanged { flow_id: None }).await;
        }
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
        for change in &changes {
            if let Some(old) = &change.old
                && old.flow_id != change.new.flow_id
            {
                self.route_service.clear_flow_wan_targets(old.flow_id).await;
            }
        }
        self.sync_all_flow_wan_targets().await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow_matches().await;
        {
            let _guard = self.target_sync.lock().await;
            self.route_service.clear_flow_wan_targets(old.flow_id).await;
        }
        self.sync_all_flow_wan_targets().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::flow::dataplane::NoopFlowRuleDataplane;
    use landscape_common::sys_service::route_service::{
        RouteOwner, RouteTargetInfo, WanRouteTarget,
    };

    #[tokio::test]
    async fn deleting_default_owner_immediately_refreshes_followed_dns_binding() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let routes = landscape_core::route::test_used_ip_route();
        let primary = Uuid::new_v4();
        let backup = Uuid::new_v4();
        for (id, name, index, default) in
            [(primary, "wan-main", 1, true), (backup, "wan-backup", 2, false)]
        {
            routes
                .insert_ipv4_wan_route(
                    &RouteOwner::Link(id),
                    WanRouteTarget::link(
                        index,
                        RouteTargetInfo::new_gateway_v4(
                            u32::from(index),
                            name,
                            None,
                            format!("192.0.2.{index}").parse().unwrap(),
                            "192.0.2.254".parse().unwrap(),
                            default,
                        ),
                    ),
                )
                .await;
        }
        let config: FlowConfig = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "enable": true, "flow_id": 9,
            "flow_match_rules": [], "remark": "test",
            "flow_targets": [{"target": {"t": "interface", "link_id": backup, "name": "wan-backup"}, "weight": 1}],
            "failover": {"mode": "primary_backup", "bind_default_flow": true}
        })).unwrap();
        provider.flow_rule_store().upsert(config.clone()).await.unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        // Construct without periodic observers: the deletion itself must
        // refresh the binding and notify DNS, with no timer/route event help.
        let service = FlowRuleService {
            store: provider.flow_rule_store(),
            dns_events_tx: tx,
            route_service: routes,
            dataplane: Arc::new(NoopFlowRuleDataplane),
            target_sync: Default::default(),
            dns_bindings: Default::default(),
        };
        service.sync_all_flow_wan_targets().await;
        assert_eq!(service.route_service.dns_wan_binding(0).await.ipv4.unwrap().0, "wan-backup");
        while rx.try_recv().is_ok() {}
        service.delete_flow_cascade(config.id).await.unwrap();
        let bindings = service.dns_bindings.lock().unwrap();
        assert_eq!(
            bindings.iter().find(|(id, _)| *id == 0).unwrap().1.ipv4.as_ref().unwrap().0,
            "wan-main"
        );
        assert!(!bindings.iter().any(|(id, _)| *id == 9));
        assert!(matches!(rx.try_recv(), Ok(DnsEvent::RulesChanged { flow_id: None })));
    }
}
