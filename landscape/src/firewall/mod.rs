use landscape_common::database::LandscapeStore;
use landscape_common::service::manager::ServiceManager;
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    firewall::service::FirewallServiceConfig,
    observer::IfaceObserverAction,
    service::{
        controller::ControllerService, manager::ServiceStarterTrait, ServiceStatus, WatchService,
    },
};

use landscape_database::{
    firewall::repository::FirewallServiceRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::broadcast;

use crate::iface::get_iface_by_name;

pub mod blacklist;
pub mod blacklist_service;

#[derive(Clone, Default)]
pub struct FirewallService {}

#[async_trait::async_trait]
impl ServiceStarterTrait for FirewallService {
    type Config = FirewallServiceConfig;

    async fn start(&self, config: FirewallServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                spawn_task_with_resource(
                    task_label::task::FIREWALL_RUN,
                    iface_name.clone(),
                    async move {
                        create_firewall_service(
                            iface_name,
                            iface.index as i32,
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

pub async fn create_firewall_service(
    iface_name: String,
    ifindex: i32,
    has_mac: bool,
    service_status: WatchService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let firewall = match landscape_ebpf::stages::firewall::init_firewall(ifindex as u32, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start firewall for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(firewall);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct FirewallServiceManagerService {
    store: FirewallServiceRepository,
    service: ServiceManager<FirewallService>,
}

impl ControllerService for FirewallServiceManagerService {
    type Id = String;
    type Config = FirewallServiceConfig;
    type DatabseAction = FirewallServiceRepository;
    type H = FirewallService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl FirewallServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
    ) -> Self {
        let store = store_service.firewall_service_store();
        let service =
            ServiceManager::init(store.list().await.unwrap(), FirewallService::default()).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::FIREWALL_OBSERVER, async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Firewall service");
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

        let store = store_service.firewall_service_store();
        Self { service, store }
    }
}
