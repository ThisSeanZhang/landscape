use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    config_service::geo::GeoFileCacheKey,
    database::error::DbError,
    database::store::Change,
    event::dns::DstIpEvent,
    flow::{WanIPRuleSource, dataplane::FlowRuleDataplane, ip_mark::WanIpRuleConfig},
    service::controller::{ConfigStoreController, ConfigStoreFlowController},
};
use landscape_database::{
    dst_ip_rule::repository::DstIpRuleRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::geo::ip_service::GeoIpService;

#[derive(Clone)]
pub struct DstIpRuleService {
    store: DstIpRuleRepository,
    geo_ip_service: GeoIpService,
    dataplane: Arc<dyn FlowRuleDataplane>,
}

impl DstIpRuleService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        geo_ip_service: GeoIpService,
        mut receiver: broadcast::Receiver<DstIpEvent>,
        dataplane: Arc<dyn FlowRuleDataplane>,
    ) -> Self {
        let store = store.dst_ip_rule_store();
        let dst_ip_rule_service = Self { store, geo_ip_service, dataplane };
        dst_ip_rule_service.apply_loaded_configs().await;

        let dst_ip_rule_service_clone = dst_ip_rule_service.clone();
        spawn_task(task_label::task::FLOW_DST_IP_OBSERVER, async move {
            while let Ok(event) = receiver.recv().await {
                match event {
                    DstIpEvent::GeoIpUpdated { changed_keys } => {
                        tracing::info!(
                            "refresh dst ip rules for {} changed geo key(s)",
                            changed_keys.len()
                        );
                        let configs = match dst_ip_rule_service_clone.list().await {
                            Ok(configs) => configs,
                            Err(error) => {
                                tracing::error!(
                                    "failed to load dst ip rules for geo update: {error:?}"
                                );
                                continue;
                            }
                        };
                        let affected_flows = affected_flow_ids(&configs, &changed_keys);
                        if affected_flows.is_empty() {
                            continue;
                        }
                        let affected_configs = configs
                            .into_iter()
                            .filter(|rule| affected_flows.contains(&rule.flow_id))
                            .collect();
                        dst_ip_rule_service_clone.apply_configs(affected_configs).await;
                    }
                }
            }
        });

        dst_ip_rule_service
    }

    async fn apply_loaded_configs(&self) {
        let configs = match self.list().await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load dst ip rules: {error:?}");
                Vec::new()
            }
        };
        self.apply_configs(configs).await;
    }

    async fn refresh_flow(&self, flow_id: u32) {
        let rules = match self.list_flow_configs(flow_id).await {
            Ok(rules) => rules,
            Err(error) => {
                tracing::error!("failed to load dst ip rules for flow {flow_id}: {error:?}");
                return;
            }
        };
        update_flow_dst_ip_map(self.geo_ip_service.clone(), self.dataplane.clone(), flow_id, rules)
            .await;
    }

    async fn apply_configs(&self, configs: Vec<WanIpRuleConfig>) {
        let mut flow_ids = HashSet::new();
        let mut rule_map: HashMap<u32, Vec<WanIpRuleConfig>> = HashMap::new();

        for r in configs.into_iter() {
            flow_ids.insert(r.flow_id);
            rule_map.entry(r.flow_id).or_default().push(r);
        }

        for flow_id in flow_ids {
            let rules = rule_map.remove(&flow_id).unwrap_or_default();
            let geo_ip_service = self.geo_ip_service.clone();
            update_flow_dst_ip_map(geo_ip_service, self.dataplane.clone(), flow_id, rules).await;
        }
        // TODO: 应当只清理当前 Flow 的缓存
        self.dataplane.invalidate_lan_cache();
    }
}

impl ConfigStoreFlowController for DstIpRuleService {}

#[async_trait::async_trait]
impl ConfigStoreController for DstIpRuleService {
    type Id = Uuid;

    type Config = WanIpRuleConfig;

    type Store = DstIpRuleRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn checked_set(&self, config: WanIpRuleConfig) -> Result<WanIpRuleConfig, DbError> {
        let change = self.store.checked_upsert_flow_rule(config).await?;
        self.notify_changed(vec![change.clone()]).await;
        Ok(change.new)
    }

    async fn checked_set_list(&self, configs: Vec<WanIpRuleConfig>) -> Result<(), DbError> {
        let changes = self.store.checked_upsert_flow_rules(configs).await?;
        self.notify_changed(changes).await;
        Ok(())
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        if changes.len() == 1 {
            let flow_id = changes[0].new.flow_id;
            self.refresh_flow(flow_id).await;
        } else {
            self.apply_configs(changes.into_iter().map(|c| c.new).collect()).await;
        }
    }

    async fn notify_deleted(&self, old: Self::Config) {
        self.refresh_flow(old.flow_id).await;
    }
}

fn affected_flow_ids(
    configs: &[WanIpRuleConfig],
    changed_keys: &HashSet<GeoFileCacheKey>,
) -> HashSet<u32> {
    configs
        .iter()
        .filter(|rule| rule.enable && rule_references_changed_geo(rule, changed_keys))
        .map(|rule| rule.flow_id)
        .collect()
}

fn rule_references_changed_geo(
    rule: &WanIpRuleConfig,
    changed_keys: &HashSet<GeoFileCacheKey>,
) -> bool {
    rule.source.iter().any(|source| match source {
        WanIPRuleSource::GeoKey(key) => {
            changed_keys.iter().any(|changed| key.matches_file_cache_key(changed))
        }
        WanIPRuleSource::Config(_) => false,
    })
}

async fn update_flow_dst_ip_map(
    geo_ip_service: GeoIpService,
    dataplane: Arc<dyn FlowRuleDataplane>,
    flow_id: u32,
    rules: Vec<WanIpRuleConfig>,
) {
    let mut rules: Vec<WanIpRuleConfig> = rules.into_iter().filter(|r| r.enable).collect();
    rules.sort_by_key(|a| a.index);
    tracing::info!("[flow_id: {flow_id}] update dst ip rules: {rules:?}");
    let result = geo_ip_service.convert_config_to_runtime_rule(rules).await;
    dataplane.set_dst_ip_marks(flow_id, result);
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use landscape_common::{
        config_service::geo::{GeoConfigKey, GeoFileCacheKey},
        flow::{IpConfig, WanIPRuleSource, mark::FlowMark},
    };
    use uuid::Uuid;

    use super::{WanIpRuleConfig, affected_flow_ids};

    fn geo_key(key: &str) -> GeoConfigKey {
        GeoConfigKey {
            name: "geoip".to_string(),
            key: key.to_string(),
            inverse: false,
            attribute_key: None,
        }
    }

    fn rule(flow_id: u32, enable: bool, source: Vec<WanIPRuleSource>) -> WanIpRuleConfig {
        WanIpRuleConfig {
            id: Uuid::new_v4(),
            name: None,
            index: 0,
            enable,
            mark: FlowMark::default(),
            source,
            remark: String::new(),
            flow_id,
            override_dns: false,
            update_at: 0.0,
        }
    }

    #[test]
    fn only_flows_referencing_changed_geo_keys_are_selected() {
        let configs = vec![
            rule(1, true, vec![WanIPRuleSource::GeoKey(geo_key("CN"))]),
            rule(2, true, vec![WanIPRuleSource::GeoKey(geo_key("US"))]),
            rule(
                3,
                true,
                vec![WanIPRuleSource::Config(IpConfig {
                    ip: "192.0.2.1".parse().unwrap(),
                    prefix: 24,
                })],
            ),
            rule(4, false, vec![WanIPRuleSource::GeoKey(geo_key("CN"))]),
        ];
        let changed =
            HashSet::from([GeoFileCacheKey { name: "geoip".to_string(), key: "cn".to_string() }]);

        assert_eq!(affected_flow_ids(&configs, &changed), HashSet::from([1]));
    }
}
