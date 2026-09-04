use std::collections::{HashMap, HashSet};

use landscape_common::{
    event::dns::DstIpEvent,
    flow::ip_mark::WanIpRuleConfig,
    service::controller::{ConfigController, FlowConfigController},
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
}

impl DstIpRuleService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        geo_ip_service: GeoIpService,
        mut receiver: broadcast::Receiver<DstIpEvent>,
    ) -> Self {
        let store = store.dst_ip_rule_store();
        let dst_ip_rule_service = Self { store, geo_ip_service };
        dst_ip_rule_service.update_many_config(dst_ip_rule_service.list().await).await;
        let dst_ip_rule_service_clone = dst_ip_rule_service.clone();
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                match event {
                    DstIpEvent::GeoIpUpdated => {
                        tracing::info!("refresh dst ip rule");
                        dst_ip_rule_service_clone
                            .update_many_config(dst_ip_rule_service_clone.list().await)
                            .await;
                    }
                }
            }
        });

        dst_ip_rule_service
    }
}

impl FlowConfigController for DstIpRuleService {}

#[async_trait::async_trait]
impl ConfigController for DstIpRuleService {
    type Id = Uuid;

    type Config = WanIpRuleConfig;

    type DatabseAction = DstIpRuleRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn update_one_config(&self, config: Self::Config) {
        let flow_id = config.flow_id;
        let rules = self.list_flow_configs(flow_id).await;
        update_flow_dst_ip_map(self.geo_ip_service.clone(), flow_id, rules).await;
    }
    async fn delete_one_config(&self, config: Self::Config) {
        let flow_id = config.flow_id;
        let rules = self.list_flow_configs(flow_id).await;
        update_flow_dst_ip_map(self.geo_ip_service.clone(), flow_id, rules).await;
    }

    async fn update_many_config(&self, new_configs: Vec<Self::Config>) {
        let mut flow_ids = HashSet::new();
        let mut rule_map: HashMap<u32, Vec<WanIpRuleConfig>> = HashMap::new();

        for r in new_configs.into_iter() {
            if !flow_ids.contains(&r.flow_id) {
                flow_ids.insert(r.flow_id);
            }
            match rule_map.entry(r.flow_id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(r),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(vec![r]);
                }
            }
        }

        for flow_id in flow_ids {
            let rules = rule_map.remove(&flow_id).unwrap_or_default();
            let geo_ip_service = self.geo_ip_service.clone();
            update_flow_dst_ip_map(geo_ip_service, flow_id, rules).await;
        }
        // TODO: 应当只清理当前 Flow 的缓存
        landscape_ebpf::maps::route::cache::recreate_route_lan_cache_inner_map();
    }
}

async fn update_flow_dst_ip_map(
    geo_ip_service: GeoIpService,
    flow_id: u32,
    rules: Vec<WanIpRuleConfig>,
) {
    let mut rules: Vec<WanIpRuleConfig> = rules.into_iter().filter(|r| r.enable).collect();
    rules.sort_by_key(|a| a.index);
    tracing::info!("[flow_id: {flow_id}] update dst ip rules: {rules:?}");
    let result = geo_ip_service.convert_config_to_runtime_rule(rules).await;
    landscape_ebpf::maps::flow_wanip::add_wan_ip_mark(flow_id, result);
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use landscape_common::{
        config_service::geo::{GeoFileCacheKey, GeoIpConfig},
        store::storev4::StoreFileManager,
        LANDSCAPE_GEO_CACHE_TMP_DIR,
    };

    #[test]
    pub fn load_ip_test() {
        let mut ip_store: StoreFileManager<GeoFileCacheKey, GeoIpConfig> = StoreFileManager::new(
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
