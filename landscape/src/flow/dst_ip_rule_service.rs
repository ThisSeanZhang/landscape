use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use landscape_common::{
    database::store::Change,
    event::dns::DstIpEvent,
    flow::{dataplane::FlowRuleDataplane, ip_mark::WanIpRuleConfig},
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
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                match event {
                    DstIpEvent::GeoIpUpdated => {
                        tracing::info!("refresh dst ip rule");
                        dst_ip_rule_service_clone.apply_loaded_configs().await;
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

    use std::path::PathBuf;

    use landscape_common::{
        config_service::geo::{GeoFileCacheKey, GeoIpConfig},
        geo_cache::file_store::GeoCacheStore,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };

    #[test]
    pub fn load_ip_test() {
        let mut ip_store: GeoCacheStore<GeoFileCacheKey, GeoIpConfig> = GeoCacheStore::new(
            PathBuf::from("/root/.landscape-router").join(LANDSCAPE_GEO_CACHE_TMP_DIR),
            "ip".to_string(),
        );

        let all = ip_store.list();

        for config in all {
            for c in config.values {
                if c.ip.is_ipv6() {
                    println!("key: {}, name: {}", config.key, config.name);
                    break;
                }
            }
        }
    }
}
