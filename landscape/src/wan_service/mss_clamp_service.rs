use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    iface::mss_clamp::MSSClampServiceConfig,
    observer::IfaceObserverAction,
    service::{
        controller::ControllerService,
        manager::{ServiceManager, ServiceStarterTrait},
        ServiceStatus, WatchService,
    },
};
use landscape_database::{
    mss_clamp::repository::MssClampServiceRepository, provider::LandscapeDBServiceProvider,
};

use crate::get_iface_by_name;

#[derive(Clone, Default)]
pub struct MssClampService;

#[async_trait::async_trait]
impl ServiceStarterTrait for MssClampService {
    type Config = MSSClampServiceConfig;

    async fn start(&self, config: MSSClampServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                spawn_task_with_resource(
                    task_label::task::MSS_CLAMP_RUN,
                    iface_name.clone(),
                    async move {
                        run_mss_clamp(
                            iface_name,
                            iface.index as i32,
                            config.clamp_size,
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

pub async fn run_mss_clamp(
    iface_name: String,
    ifindex: i32,
    mtu_size: u16,
    has_mac: bool,
    service_status: WatchService,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let mss_clamp = match landscape_ebpf::stages::mss::init_mss(ifindex as u32, mtu_size, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Stop);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}

#[derive(Clone)]
pub struct MssClampServiceManagerService {
    store: MssClampServiceRepository,
    service: ServiceManager<MssClampService>,
}

impl ControllerService for MssClampServiceManagerService {
    type Id = String;
    type Config = MSSClampServiceConfig;
    type DatabseAction = MssClampServiceRepository;
    type H = MssClampService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl MssClampServiceManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
    ) -> Self {
        let store = store_service.mss_clamp_service_store();
        let service = ServiceManager::init(store.list().await.unwrap(), Default::default()).await;

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
        Self { service, store }
    }
}
