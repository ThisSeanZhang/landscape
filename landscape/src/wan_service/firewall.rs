use std::sync::Arc;

use landscape_common::database::LandscapeStore;
use landscape_common::database::error::DbError;
use landscape_common::service::manager::ServiceManager;
use landscape_common::{
    concurrency::{spawn_task, task_label},
    event::hub::iface::IfaceObserverAction,
    service::{
        ServiceStatus, WatchService,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::ServiceStarterTrait,
    },
    wan_service::firewall::dataplane::FirewallDataplane,
    wan_service::firewall::service::FirewallServiceConfig,
};

use landscape_common::event::hub::IfaceEventReader;
use landscape_database::{
    firewall::repository::FirewallServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;

#[derive(Clone)]
pub struct FirewallService {
    dataplane: Arc<dyn FirewallDataplane>,
}

#[async_trait::async_trait]
impl ServiceStarterTrait for FirewallService {
    type Config = FirewallServiceConfig;

    async fn start(&self, config: FirewallServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                // 契约:返回前进入 Staring,任务内直接 Staring → Running/Failed
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = config.iface_name.clone();
                let dataplane = self.dataplane.clone();
                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task_with_resource(
                    task_label::task::FIREWALL_RUN,
                    iface_name.clone(),
                    async move {
                        create_firewall_service(
                            iface_name,
                            iface.index as i32,
                            iface.mac.is_some(),
                            task_status,
                            dataplane,
                        )
                        .await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                service_status.just_change_status(ServiceStatus::Staring);
                service_status.just_change_status(ServiceStatus::Failed);
            }
        } else {
            service_status.just_change_status(ServiceStatus::Disabled);
        }

        service_status
    }
}

pub async fn create_firewall_service(
    iface_name: String,
    ifindex: i32,
    has_mac: bool,
    service_status: WatchService,
    dataplane: Arc<dyn FirewallDataplane>,
) {
    let firewall = match dataplane.attach(ifindex as u32, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start firewall for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    service_status.stop_token().cancelled().await;
    tracing::info!("Received external stop signal");

    drop(firewall);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct FirewallServiceManagerService {
    store: FirewallServiceRepository,
    service: ServiceManager<FirewallService>,
}

#[async_trait::async_trait]
impl ConfigStoreController for FirewallServiceManagerService {
    type Id = String;
    type Config = FirewallServiceConfig;
    type Store = FirewallServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for FirewallServiceManagerService {
    type H = FirewallService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl FirewallServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        dataplane: Arc<dyn FirewallDataplane>,
    ) -> Result<Self, DbError> {
        let store = store_service.firewall_service_store();
        let service =
            ServiceManager::init(store.list().await?, FirewallService { dataplane }).await;

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
        Ok(Self { service, store })
    }
}
