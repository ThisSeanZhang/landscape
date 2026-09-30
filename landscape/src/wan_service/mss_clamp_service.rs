use std::sync::Arc;

use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::{
    concurrency::{spawn_task, task_label},
    event::hub::iface::IfaceObserverAction,
    service::{
        ServiceHandle, ServiceStatus,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::{ServiceManager, ServiceStarterTrait},
    },
    wan_service::mss_clamp::MSSClampServiceConfig,
    wan_service::mss_clamp::dataplane::MssClampDataplane,
};
use landscape_database::{
    mss_clamp::repository::MssClampServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;

#[derive(Clone)]
pub struct MssClampService {
    dataplane: Arc<dyn MssClampDataplane>,
}

#[async_trait::async_trait]
impl ServiceStarterTrait for MssClampService {
    type Config = MSSClampServiceConfig;

    async fn start(&self, config: MSSClampServiceConfig) -> ServiceHandle {
        let service_status = ServiceHandle::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                // 契约:返回前进入 Staring,任务内直接 Staring → Running/Stop
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = config.iface_name.clone();
                let dataplane = self.dataplane.clone();
                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task_with_resource(
                    task_label::task::MSS_CLAMP_RUN,
                    iface_name.clone(),
                    async move {
                        run_mss_clamp(
                            iface_name,
                            iface.index as i32,
                            config.clamp_size,
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

pub async fn run_mss_clamp(
    iface_name: String,
    ifindex: i32,
    mtu_size: u16,
    has_mac: bool,
    service_status: ServiceHandle,
    dataplane: Arc<dyn MssClampDataplane>,
) {
    let mss_clamp = match dataplane.attach(ifindex as u32, mtu_size, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Stop);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    service_status.stop_token().cancelled().await;
    tracing::info!("Received external stop signal");

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct MssClampServiceManagerService {
    store: MssClampServiceRepository,
    service: ServiceManager<MssClampService>,
}

#[async_trait::async_trait]
impl ConfigStoreController for MssClampServiceManagerService {
    type Id = String;
    type Config = MSSClampServiceConfig;
    type Store = MssClampServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for MssClampServiceManagerService {
    type H = MssClampService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl MssClampServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        dataplane: Arc<dyn MssClampDataplane>,
    ) -> Result<Self, DbError> {
        let store = store_service.mss_clamp_service_store();
        let service =
            ServiceManager::init(store.list().await?, MssClampService { dataplane }).await;

        let service_clone = service.clone();
        spawn_task(task_label::task::MSS_CLAMP_OBSERVER, async move {
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

        let store = store_service.mss_clamp_service_store();
        Ok(Self { service, store })
    }
}
