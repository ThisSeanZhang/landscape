use landscape_common::database::{LandscapeDBTrait, LandscapeServiceDBTrait};
use landscape_common::service::service_manager_v2::ServiceManager;
use landscape_common::{
    config::firewall::FirewallServiceConfig,
    observer::IfaceObserverAction,
    service::{
        controller_service_v2::ControllerService, service_manager_v2::ServiceStarterTrait,
        DefaultServiceStatus, DefaultWatchServiceStatus, ServiceStatus,
    },
};

use landscape_database::{
    firewall::repository::FirewallServiceRepository, provider::LandscapeDBServiceProvider,
};
use tokio::sync::{broadcast, oneshot};

use crate::iface::get_iface_by_name;

pub mod rules;

#[derive(Clone, Default)]
pub struct FirewallService {}

#[async_trait::async_trait]
impl ServiceStarterTrait for FirewallService {
    type Status = DefaultServiceStatus;

    type Config = FirewallServiceConfig;

    async fn start(&self, config: FirewallServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                tokio::spawn(async move {
                    create_firewall_service(iface.index as i32, iface.mac.is_some(), status_clone)
                        .await
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

pub async fn create_firewall_service(
    ifindex: i32,
    has_mac: bool,
    service_status: DefaultWatchServiceStatus,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();
    service_status.just_change_status(ServiceStatus::Running);
    let service_status_clone = service_status.clone();
    tokio::spawn(async move {
        let stop_wait = service_status_clone.wait_to_stopping();
        tracing::info!("等待外部停止信号");
        let _ = stop_wait.await;
        tracing::info!("接收外部停止信号");
        let _ = tx.send(());
        tracing::info!("向内部发送停止信号");
    });
    std::thread::spawn(move || {
        // if let Err(e) = landscape_ebpf::firewall::new_firewall(ifindex, has_mac, rx) {
        //     tracing::error!("{e:?}");
        // }
        if let Err(e) = landscape_ebpf::firewall::v2::firewall_v2(ifindex, has_mac, rx) {
            tracing::error!("{e:?}");
        }
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });
    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");
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
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} Firewall service");
                        let service_config = if let Some(service_config) =
                            store.find_by_iface_name(iface_name.clone()).await.unwrap()
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
