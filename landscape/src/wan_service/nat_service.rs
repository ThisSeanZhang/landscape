use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::IfaceEventReader;
use landscape_common::observer::IfaceObserverAction;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::{
    concurrency::{spawn_task, spawn_task_with_resource, task_label},
    iface::nat::{NatConfig, NatServiceConfig},
    service::{manager::ServiceStarterTrait, ServiceStatus, WatchService},
};
use landscape_database::nat::repository::NatServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;

use crate::get_iface_by_name;

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
    ) -> Self {
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
        Self { service, store }
    }
}
