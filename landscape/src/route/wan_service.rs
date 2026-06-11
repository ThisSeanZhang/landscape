use landscape_common::database::LandscapeStore;
use landscape_common::route::wan::RouteWanServiceConfig;
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    observer::IfaceObserverAction,
    service::{
        controller::ControllerService,
        manager::{ServiceManager, ServiceStarterTrait},
        ServiceStatus, WatchService,
    },
};
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::route_wan::repository::RouteWanServiceRepository;
use tokio::sync::broadcast;

use crate::iface::get_iface_by_name;

#[derive(Clone)]
#[allow(dead_code)]
pub struct RouteWanService {}

impl RouteWanService {
    pub fn new() -> Self {
        RouteWanService {}
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for RouteWanService {
    type Config = RouteWanServiceConfig;

    async fn start(&self, config: RouteWanServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                spawn_task_with_resource(
                    task_label::task::ROUTE_WAN_RUN,
                    iface_name.clone(),
                    async move {
                        create_route_wan_service(
                            iface_name,
                            iface.index,
                            iface.mac.is_some(),
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

pub async fn create_route_wan_service(
    iface_name: String,
    ifindex: u32,
    has_mac: bool,
    service_status: WatchService,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    tracing::info!("start route wan at ifindex: {ifindex}");
    landscape_ebpf::map_setting::redirect_able::del_xdp_redirect_able(ifindex);

    let mut xdp_handle: Option<landscape_ebpf::chain::xdp_wan_route::XdpWanRouteHandle> = None;

    let xdp_ok = match landscape_ebpf::chain::xdp_wan_route::init_xdp_wan_route(ifindex, has_mac) {
        Ok(handle) => {
            landscape_ebpf::map_setting::redirect_able::set_xdp_redirect_able(ifindex, true);
            tracing::info!("xdp handoff enabled for {iface_name}");
            xdp_handle = Some(handle);
            true
        }
        Err(err) => {
            tracing::warn!(
                "failed to start xdp wan route for {iface_name}: {err}, starting TC only"
            );
            false
        }
    };

    let tc_handle =
        match landscape_ebpf::chain::tc_wan_route::init_tc_wan_route(ifindex, has_mac, xdp_ok) {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!("failed to start tc wan route for {iface_name}: {err}");
                service_status.just_change_status(ServiceStatus::Failed);
                landscape_ebpf::map_setting::redirect_able::del_xdp_redirect_able(ifindex);
                return;
            }
        };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Receiving external stop signal");
    drop(xdp_handle);
    drop(tc_handle);
    landscape_ebpf::map_setting::redirect_able::del_xdp_redirect_able(ifindex);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct RouteWanServiceManagerService {
    store: RouteWanServiceRepository,
    service: ServiceManager<RouteWanService>,
}

impl ControllerService for RouteWanServiceManagerService {
    type Id = String;
    type Config = RouteWanServiceConfig;
    type DatabseAction = RouteWanServiceRepository;
    type H = RouteWanService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl RouteWanServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
    ) -> Self {
        let store = store_service.route_wan_service_store();
        let server_starter = RouteWanService::new();
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::ROUTE_WAN_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Route Wan service");
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

        let store = store_service.route_wan_service_store();
        Self { service, store }
    }
}
