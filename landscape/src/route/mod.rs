use core::mem::drop;
use std::{collections::HashMap, sync::Arc};

use landscape_common::{
    config::FlowId,
    event::route::RouteEvent,
    flow::{config::FlowConfig, FlowTarget},
    route::{LanRouteInfo, RouteTargetInfo},
};
use landscape_database::flow_rule::repository::FlowConfigRepository;
use landscape_ebpf::map_setting::route::{add_lan_route, del_lan_route};
use tokio::sync::{mpsc, RwLock};

use landscape_common::database::LandscapeDBTrait;

type ShareRwLock<T> = Arc<RwLock<T>>;
#[derive(Clone)]
pub struct IpRouteService {
    flow_repo: FlowConfigRepository,
    ipv4_wan_ifaces: ShareRwLock<HashMap<String, RouteTargetInfo>>,
    ipv6_wan_ifaces: ShareRwLock<HashMap<String, RouteTargetInfo>>,

    ipv4_lan_ifaces: ShareRwLock<HashMap<String, LanRouteInfo>>,
    ipv6_lan_ifaces: ShareRwLock<HashMap<String, LanRouteInfo>>,
}

impl IpRouteService {
    pub fn new(
        mut route_event_sender: mpsc::Receiver<RouteEvent>,
        flow_repo: FlowConfigRepository,
    ) -> Self {
        let service = IpRouteService {
            flow_repo,
            ipv4_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv4_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
        };
        let route_service = service.clone();
        tokio::spawn(async move {
            while let Some(event) = route_event_sender.recv().await {
                use std::option::Option::None;
                //
                match event {
                    RouteEvent::FlowRuleUpdate { flow_id: Some(flow_id) } => {
                        if let Ok(Some(flow_config)) =
                            route_service.flow_repo.find_by_flow_id(flow_id).await
                        {
                            let ipv4_wan_infos = {
                                let read_lock = route_service.ipv4_wan_ifaces.read().await;
                                read_lock.clone()
                            };

                            let ipv6_wan_infos = {
                                let read_lock = route_service.ipv6_wan_ifaces.read().await;
                                read_lock.clone()
                            };

                            let flow_configs = vec![flow_config];
                            refresh_ipv4_target_bpf_map(&flow_configs, ipv4_wan_infos);
                            refresh_ipv6_target_bpf_map(&flow_configs, ipv6_wan_infos);
                        }
                    }
                    RouteEvent::FlowRuleUpdate { flow_id: None } => {
                        let flow_configs = route_service.flow_repo.list().await.unwrap_or_default();
                        let ipv4_wan_infos = {
                            let read_lock = route_service.ipv4_wan_ifaces.read().await;
                            read_lock.clone()
                        };

                        let ipv6_wan_infos = {
                            let read_lock = route_service.ipv6_wan_ifaces.read().await;
                            read_lock.clone()
                        };

                        refresh_ipv4_target_bpf_map(&flow_configs, ipv4_wan_infos);
                        refresh_ipv6_target_bpf_map(&flow_configs, ipv6_wan_infos);
                    }
                }
            }
        });
        service
    }

    pub async fn remove_all_wan_docker(&self) {
        {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            lock.retain(|_, value| !value.is_docker);
        }

        {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            lock.retain(|_, value| !value.is_docker);
        }
    }

    pub async fn print_wan_ifaces(&self) {
        {
            let lock = self.ipv4_wan_ifaces.read().await;
            tracing::info!("ipv4 wan ifaces: {:?}", lock)
        }

        {
            let lock = self.ipv6_wan_ifaces.read().await;
            tracing::info!("ipv6 wan ifaces: {:?}", lock)
        }
    }

    pub async fn insert_ipv6_lan_route(&self, key: &str, info: LanRouteInfo) {
        let mut lock = self.ipv6_lan_ifaces.write().await;
        add_lan_route(info.clone());
        lock.insert(key.to_string(), info);
        drop(lock);
    }

    pub async fn insert_ipv4_lan_route(&self, key: &str, info: LanRouteInfo) {
        let mut lock = self.ipv4_lan_ifaces.write().await;
        add_lan_route(info.clone());
        lock.insert(key.to_string(), info);
        drop(lock);
    }

    pub async fn remove_ipv6_lan_route(&self, key: &str) {
        let mut lock = self.ipv6_lan_ifaces.write().await;
        let result = lock.remove(key);
        drop(lock);
        if let Some(info) = result {
            del_lan_route(info);
        }
    }

    pub async fn remove_ipv4_lan_route(&self, key: &str) {
        let mut lock = self.ipv4_lan_ifaces.write().await;
        let result = lock.remove(key);
        drop(lock);
        if let Some(info) = result {
            del_lan_route(info);
        }
    }

    pub async fn insert_ipv6_wan_route(&self, key: &str, info: RouteTargetInfo) {
        let mut refresh_default_router = info.default_route;
        let target = info.get_flow_target();
        let mut lock = self.ipv6_wan_ifaces.write().await;
        if let Some(old_info) = lock.insert(key.to_string(), info) {
            refresh_default_router = refresh_default_router || old_info.default_route;
        }
        drop(lock);
        self.refresh_ipv6_target_map(target).await;
        if refresh_default_router {
            self.refresh_default_router().await;
        }
    }

    pub async fn insert_ipv4_wan_route(&self, key: &str, info: RouteTargetInfo) {
        let mut refresh_default_router = info.default_route;
        let target = info.get_flow_target();
        let mut lock = self.ipv4_wan_ifaces.write().await;
        if let Some(old_info) = lock.insert(key.to_string(), info) {
            refresh_default_router = refresh_default_router || old_info.default_route;
        }
        drop(lock);
        self.refresh_ipv4_target_map(target).await;
        if refresh_default_router {
            self.refresh_default_router().await;
        }
    }

    pub async fn remove_ipv4_wan_route(&self, key: &str) {
        let mut lock = self.ipv4_wan_ifaces.write().await;
        let result = lock.remove(key);
        drop(lock);
        if let Some(info) = result {
            self.refresh_ipv4_target_map(info.get_flow_target()).await;
            if info.default_route {
                self.refresh_default_router().await;
            }
        }
    }

    pub async fn remove_ipv6_wan_route(&self, key: &str) {
        let mut lock = self.ipv6_wan_ifaces.write().await;
        let result = lock.remove(key);
        drop(lock);
        if let Some(info) = result {
            self.refresh_ipv6_target_map(info.get_flow_target()).await;
            if info.default_route {
                self.refresh_default_router().await;
            }
        }
    }

    pub async fn refresh_default_router(&self) {
        let wan_ifaces = self.ipv4_wan_ifaces.read().await;
        let route = wan_ifaces.values().find(|e| e.default_route);
        if let Some(route) = route {
            landscape_ebpf::map_setting::route::add_wan_route(0, route.clone());
        }
        drop(wan_ifaces);
        let wan_ifaces = self.ipv6_wan_ifaces.read().await;
        let route = wan_ifaces.values().find(|e| e.default_route);
        if let Some(route) = route {
            landscape_ebpf::map_setting::route::add_wan_route(0, route.clone());
        }
    }

    pub async fn refresh_ipv4_target_map(&self, t: FlowTarget) {
        let flow_configs = self.flow_repo.find_by_target(t).await.unwrap_or_default();

        let ipv4_wan_infos = {
            let read_lock = self.ipv4_wan_ifaces.read().await;
            read_lock.clone()
        };

        refresh_ipv4_target_bpf_map(&flow_configs, ipv4_wan_infos);
    }
    pub async fn refresh_ipv6_target_map(&self, t: FlowTarget) {
        let flow_configs = self.flow_repo.find_by_target(t).await.unwrap_or_default();

        let ipv6_wan_infos = {
            let read_lock = self.ipv6_wan_ifaces.read().await;
            read_lock.clone()
        };

        refresh_ipv6_target_bpf_map(&flow_configs, ipv6_wan_infos);
    }
}

pub fn refresh_ipv4_target_bpf_map(
    flow_configs: &Vec<FlowConfig>,
    ipv4_wan_infos: HashMap<String, RouteTargetInfo>,
) {
    let mut result: HashMap<FlowId, Vec<RouteTargetInfo>> = HashMap::new();
    for each_flow_config in flow_configs.iter() {
        let mut targets = vec![];
        if each_flow_config.enable {
            for target in each_flow_config.flow_targets.iter() {
                match target {
                    landscape_common::flow::FlowTarget::Interface { name } => {
                        if let Some(result) = ipv4_wan_infos.get(name) {
                            targets.push(result.clone());
                        }
                    }
                    landscape_common::flow::FlowTarget::Netns { container_name } => {
                        if let Some(result) = ipv4_wan_infos.get(container_name) {
                            targets.push(result.clone());
                        }
                    }
                }
            }
        }
        result.insert(each_flow_config.flow_id, targets);
    }

    tracing::info!("ipv4 flow target refresh result: {:#?}", result);
    for (flow_id, configes) in result {
        if let Some(info) = configes.get(0) {
            landscape_ebpf::map_setting::route::add_wan_route(flow_id, info.clone());
        } else {
            landscape_ebpf::map_setting::route::del_ipv4_wan_route(flow_id);
        }
    }
}

pub fn refresh_ipv6_target_bpf_map(
    flow_configs: &Vec<FlowConfig>,
    ipv6_wan_infos: HashMap<String, RouteTargetInfo>,
) {
    // IPV6
    let mut result: HashMap<FlowId, Vec<RouteTargetInfo>> = HashMap::new();
    for each_flow_config in flow_configs.iter() {
        let mut targets = vec![];
        if each_flow_config.enable {
            for target in each_flow_config.flow_targets.iter() {
                match target {
                    landscape_common::flow::FlowTarget::Interface { name } => {
                        if let Some(result) = ipv6_wan_infos.get(name) {
                            targets.push(result.clone());
                        }
                    }
                    landscape_common::flow::FlowTarget::Netns { container_name } => {
                        if let Some(result) = ipv6_wan_infos.get(container_name) {
                            targets.push(result.clone());
                        }
                    }
                }
            }
        }
        result.insert(each_flow_config.flow_id, targets);
    }

    tracing::info!("ipv6 flow target refresh result: {:#?}", result);
    for (flow_id, configes) in result {
        if let Some(info) = configes.get(0) {
            landscape_ebpf::map_setting::route::add_wan_route(flow_id, info.clone());
        } else {
            landscape_ebpf::map_setting::route::del_ipv6_wan_route(flow_id);
        }
    }
}

pub async fn test_used_ip_route() -> (mpsc::Sender<RouteEvent>, IpRouteService) {
    let db_store_provider =
        landscape_database::provider::LandscapeDBServiceProvider::mem_test_db().await;
    let flow_repo = db_store_provider.flow_rule_store();
    let (route_tx, route_rx) = mpsc::channel(1);
    let ip_route = IpRouteService::new(route_rx, flow_repo);
    (route_tx, ip_route)
}
