use landscape_common::args::LAND_HOME_PATH;
use landscape_common::dns::{DNSRuleConfig, DomainConfig};
use landscape_common::flow::{FlowConfig, PacketMatchMark};
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use landscape_common::GEO_SITE_FILE_NAME;
use serde::Serialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::server::request::LandscapeDnsRequestHandle;
use crate::server::server::DiffFlowServer;

#[derive(Serialize, Debug, Clone)]
pub struct LandscapeFiffFlowDnsService {
    pub status: DefaultWatchServiceStatus,
    #[serde(skip)]
    handlers: Arc<RwLock<HashMap<u32, LandscapeDnsRequestHandle>>>,
    #[serde(skip)]
    dispatch_rules: Arc<RwLock<HashMap<PacketMatchMark, u32>>>,
}

impl LandscapeFiffFlowDnsService {
    pub async fn new() -> Self {
        let status = DefaultWatchServiceStatus::new();
        let handlers = Arc::new(RwLock::new(HashMap::new()));
        let dispatch_rules = Arc::new(RwLock::new(HashMap::new()));
        LandscapeFiffFlowDnsService { status, handlers, dispatch_rules }
    }

    pub async fn restart(&self, listen_port: u16) {
        let service_status = self.status.clone();
        service_status.wait_stop().await;

        let handlers = self.handlers.clone();
        let dispatch_rules = self.dispatch_rules.clone();
        let mut server = DiffFlowServer::new(handlers, dispatch_rules);

        server.listen_on(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port));

        service_status.just_change_status(ServiceStatus::Staring);

        tokio::spawn(async move {
            service_status.just_change_status(ServiceStatus::Running);

            let state_end_loop = service_status.wait_to_stopping();
            let trigger_by_ui = tokio::select! {
                _ = state_end_loop => {
                    true
                },
                result = server.block_until_done() => {
                    let message = if let Err(e) = result {
                        Some(e.to_string())
                    } else {
                        None
                    };
                    tracing::error!("DNS Stop by Error: {message:?}");
                    service_status.just_change_status(ServiceStatus::Stop);
                    false
                }
            };

            if trigger_by_ui {
                tracing::info!("DNS stopping trigger by ui");
                if let Err(e) = server.shutdown_gracefully().await {
                    tracing::error!("{e:?}");
                    service_status.just_change_status(ServiceStatus::Stop);
                } else {
                    service_status.just_change_status(ServiceStatus::Stop);
                }
            }
        });
    }

    pub async fn read_geo_site_file(&self) -> HashMap<String, Vec<DomainConfig>> {
        let geo_file_path = LAND_HOME_PATH.join(GEO_SITE_FILE_NAME);

        if geo_file_path.exists() && geo_file_path.is_file() {
            landscape_protobuf::read_geo_sites(geo_file_path).await
        } else {
            tracing::error!("geo file don't exists or not a file, return empty map");
            HashMap::new()
        }
    }

    pub async fn init_handle(&self, dns_rules: Vec<DNSRuleConfig>) {
        let dns_rules: Vec<DNSRuleConfig> =
            dns_rules.into_iter().filter(|rule| rule.enable).collect();

        let mut groups: HashMap<u32, Vec<DNSRuleConfig>> = HashMap::new();

        for rule in dns_rules.into_iter() {
            groups.entry(rule.flow_id).or_default().push(rule);
        }

        let geo_map = self.read_geo_site_file().await;
        let mut write = self.handlers.write().await;

        for (flow_id, rules) in groups {
            match write.entry(flow_id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().renew_rules(rules, &geo_map);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(LandscapeDnsRequestHandle::new(rules, &geo_map, flow_id));
                }
            }
        }
    }

    pub async fn update_flow_map(&self, flow_config: &Vec<FlowConfig>) {
        let mut new_map = HashMap::new();
        for config in flow_config.iter() {
            for each_rule in config.flow_match_rules.iter() {
                new_map.insert(each_rule.clone(), config.flow_id);
            }
        }

        tracing::debug!("update dispatch_rules: {new_map:?}");
        let mut map = self.dispatch_rules.write().await;
        *map = new_map;
    }

    pub async fn flush_specific_flow_dns_rule(&self, flow_id: u32, dns_rules: Vec<DNSRuleConfig>) {
        let dns_rules: Vec<DNSRuleConfig> = dns_rules
            .into_iter()
            .filter(|rule| rule.flow_id == flow_id)
            .filter(|rule| rule.enable)
            .collect();
        let geo_map = self.read_geo_site_file().await;
        let mut write = self.handlers.write().await;

        if dns_rules.len() == 0 {
            write.remove(&flow_id);
        } else {
            match write.entry(flow_id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().renew_rules(dns_rules, &geo_map);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(LandscapeDnsRequestHandle::new(dns_rules, &geo_map, flow_id));
                }
            }
        }
    }

    pub fn stop(&self) {
        self.status.just_change_status(ServiceStatus::Stopping);
    }
}
