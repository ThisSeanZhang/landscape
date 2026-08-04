use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use landscape_common::database::LandscapeStore;
use landscape_common::ddns::IpFamily;
use landscape_common::event::hub::iface::IfaceObserverAction;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_service::nat::config::{NatConfig, NatServiceConfig};
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    service::{manager::ServiceStarterTrait, ServiceStatus, WatchService},
};
use landscape_database::nat::repository::NatServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;

use crate::get_iface_by_name;
use crate::sys_service::route::{IpRouteService, WanRouteEventKind};

fn wan_ipv4_changed(last_ips: &HashMap<String, Ipv4Addr>, owner: &str, ip: Ipv4Addr) -> bool {
    last_ips.get(owner) != Some(&ip)
}

async fn restart_nat_for_changed_wan_ipv4(
    last_ips: &mut HashMap<String, Ipv4Addr>,
    store: &NatServiceRepository,
    service: &ServiceManager<NatService>,
    owner: String,
    route: RouteTargetInfo,
) {
    let IpAddr::V4(ip) = route.iface_ip else {
        return;
    };
    if !wan_ipv4_changed(last_ips, &owner, ip) {
        return;
    }
    let previous = last_ips.get(&owner).copied();

    let service_config = match store.find_by_id(owner.clone()).await {
        Ok(Some(config)) if config.enable => Some(config),
        Ok(_) => None,
        Err(error) => {
            tracing::error!(
                iface_name = %owner,
                %error,
                "failed to load NAT config for WAN IPv4 route"
            );
            return;
        }
    };

    if let Some(service_config) = service_config {
        tracing::info!(
            iface_name = %owner,
            ifindex = route.ifindex,
            ?previous,
            new_ip = %ip,
            "restart NAT service after WAN IPv4 update"
        );
        service.update_service_wait(service_config).await;
    }
    last_ips.insert(owner, ip);
}

#[derive(Clone, Default)]
pub struct NatService;

#[async_trait::async_trait]
impl ServiceStarterTrait for NatService {
    type Config = NatServiceConfig;

    async fn start(&self, config: NatServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                spawn_task_with_resource(
                    task_label::task::NAT_RUN,
                    iface_name.clone(),
                    async move {
                        create_nat_service(
                            iface_name,
                            iface.index as i32,
                            iface.mac.is_some(),
                            config.nat_config,
                            status_clone,
                        )
                        .await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

pub async fn create_nat_service(
    iface_name: String,
    ifindex: i32,
    has_mac: bool,
    nat_config: NatConfig,
    service_status: WatchService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let nat = match landscape_ebpf::stages::nat::init_nat(ifindex as u32, has_mac, &nat_config) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start nat for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(nat);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct NatServiceManagerService {
    store: NatServiceRepository,
    service: ServiceManager<NatService>,
}

impl ControllerService for NatServiceManagerService {
    type Id = String;
    type Config = NatServiceConfig;
    type DatabseAction = NatServiceRepository;
    type H = NatService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl NatServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        route_service: IpRouteService,
    ) -> Self {
        let mut wan_route_events = route_service.subscribe_wan_route_events();
        let store = store_service.nat_service_store();
        let service = ServiceManager::init(store.list().await.unwrap(), Default::default()).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::NAT_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Nat service");
                        let service_config = if let Some(service_config) =
                            store.find_by_id(iface_name.clone()).await.unwrap()
                        {
                            service_config
                        } else {
                            continue;
                        };

                        let _ = service_clone.update_service(service_config).await;
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let store = store_service.nat_service_store();
        let service_clone = service.clone();
        spawn_task(task_label::task::NAT_WAN_ROUTE_OBSERVER, async move {
            let mut last_ips = HashMap::new();
            loop {
                let event = match wan_route_events.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "NAT WAN route observer lagged; reconciling current IPv4 routes"
                        );
                        let routes = route_service.get_all_ipv4_wan_routes().await;
                        for (owner, route) in &routes {
                            restart_nat_for_changed_wan_ipv4(
                                &mut last_ips,
                                &store,
                                &service_clone,
                                owner.clone(),
                                route.clone(),
                            )
                            .await;
                        }
                        last_ips.retain(|owner, _| routes.contains_key(owner));
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };

                if event.family != IpFamily::Ipv4 {
                    continue;
                }
                match event.kind {
                    WanRouteEventKind::Removed => {
                        last_ips.remove(&event.owner);
                    }
                    WanRouteEventKind::Upserted => {
                        let Some(route) = route_service.get_ipv4_wan_route(&event.owner).await
                        else {
                            continue;
                        };
                        restart_nat_for_changed_wan_ipv4(
                            &mut last_ips,
                            &store,
                            &service_clone,
                            event.owner,
                            route,
                        )
                        .await;
                    }
                }
            }
        });

        let store = store_service.nat_service_store();
        Self { service, store }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use super::wan_ipv4_changed;

    #[test]
    fn wan_ipv4_changes_are_compared_per_owner() {
        let mut last_ips = HashMap::new();
        let first_ip = Ipv4Addr::new(192, 0, 2, 10);

        assert!(wan_ipv4_changed(&last_ips, "wan0", first_ip));

        last_ips.insert("wan0".to_string(), first_ip);
        assert!(!wan_ipv4_changed(&last_ips, "wan0", first_ip));
        assert!(wan_ipv4_changed(&last_ips, "wan0", Ipv4Addr::new(192, 0, 2, 11)));
        assert!(wan_ipv4_changed(&last_ips, "wan1", first_ip));
    }
}
