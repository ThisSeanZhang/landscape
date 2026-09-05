use std::sync::Arc;

use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::lan_service::lan_route::dataplane::LanRouteDataplane;
use landscape_common::lan_service::lan_route::RouteLanServiceConfig;
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    event::hub::iface::IfaceObserverAction,
    service::{
        controller::ControllerService,
        manager::{ServiceManager, ServiceStarterTrait},
        ServiceStatus, WatchService,
    },
};
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::route_lan::repository::RouteLanServiceRepository;

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

#[derive(Clone)]
#[allow(dead_code)]
pub struct RouteLanService {
    route_service: IpRouteService,
    dataplane: Arc<dyn LanRouteDataplane>,
}

impl RouteLanService {
    pub fn new(route_service: IpRouteService, dataplane: Arc<dyn LanRouteDataplane>) -> Self {
        RouteLanService { route_service, dataplane }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for RouteLanService {
    type Config = RouteLanServiceConfig;

    async fn start(&self, config: RouteLanServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let route_name = format!("{}-static", config.iface_name);
                let route_service = self.route_service.clone();
                let static_routes: Vec<_> = config
                    .static_routes
                    .into_iter()
                    .flat_map(|routes| routes.into_iter())
                    .map(|e2| e2.to_lan_info(iface.index, &iface.name))
                    .collect();

                for info in static_routes {
                    route_service.insert_ipv4_lan_route(&route_name, info).await;
                }

                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                let dataplane = self.dataplane.clone();
                spawn_task_with_resource(
                    task_label::task::ROUTE_LAN_RUN,
                    iface_name.clone(),
                    async move {
                        create_route_lan_service(
                            iface_name,
                            iface.index,
                            iface.mac.is_some(),
                            status_clone,
                            dataplane,
                        )
                        .await;
                        route_service.remove_ipv4_lan_route(&route_name).await;
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

pub async fn create_route_lan_service(
    iface_name: String,
    ifindex: u32,
    has_mac: bool,
    service_status: WatchService,
    dataplane: Arc<dyn LanRouteDataplane>,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    tracing::info!("start route lan at ifindex: {ifindex}");
    dataplane.del_redirect_able(ifindex);

    let mut xdp_handle: Option<Box<dyn landscape_common::ebpf::DataplaneGuard>> = None;

    let xdp_ok = match dataplane.install_xdp_intro(ifindex, has_mac) {
        Ok(handle) => {
            dataplane.set_redirect_able(ifindex, true);
            tracing::info!("xdp handoff enabled for {iface_name}");
            xdp_handle = Some(handle);
            true
        }
        Err(err) => {
            tracing::warn!(
                "failed to start xdp lan route for {iface_name}: {err}, starting TC only"
            );
            dataplane.set_redirect_able(ifindex, false);
            false
        }
    };

    let tc_handle = match dataplane.install_tc_route(ifindex, has_mac, xdp_ok) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start tc lan route for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            dataplane.remove_xdp_roots(ifindex);
            dataplane.del_redirect_able(ifindex);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Receiving external stop signal");
    drop(xdp_handle);
    dataplane.remove_xdp_roots(ifindex);
    drop(tc_handle);
    dataplane.del_redirect_able(ifindex);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct RouteLanServiceManagerService {
    store: RouteLanServiceRepository,
    service: ServiceManager<RouteLanService>,
}

impl ControllerService for RouteLanServiceManagerService {
    type Id = String;
    type Config = RouteLanServiceConfig;
    type DatabseAction = RouteLanServiceRepository;
    type H = RouteLanService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl RouteLanServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        route_service: IpRouteService,
        mut dev_observer: IfaceEventReader,
        dataplane: Arc<dyn LanRouteDataplane>,
    ) -> Self {
        let store = store_service.route_lan_service_store();
        let server_starter = RouteLanService::new(route_service, dataplane);
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::ROUTE_LAN_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} RouteLan service");
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

        let store = store_service.route_lan_service_store();
        Self { service, store }
    }
}
