mod env;
mod supervisor;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use landscape_common::concurrency::task_label;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::{ServiceHandle, manager::ServiceStarterTrait};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_common::wan_service::pppd::PPPDServiceConfig;
use landscape_database::pppd::repository::PPPDServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

use env::{PppdEnv, PppdTimings, SystemPppdEnv};
use supervisor::run_pppd_supervisor;

#[derive(Clone)]
pub struct PPPDService {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
}

impl PPPDService {
    pub fn new(route_service: IpRouteService, addr_binding: Arc<dyn WanAddrBinding>) -> Self {
        PPPDService { route_service, addr_binding }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for PPPDService {
    type Config = PPPDServiceConfig;

    async fn start(&self, config: PPPDServiceConfig) -> ServiceHandle {
        let service_status = ServiceHandle::new();
        if config.enable {
            if get_iface_by_name(&config.attach_iface_name).await.is_some() {
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = config.iface_name.clone();
                let env: Arc<dyn PppdEnv> = Arc::new(SystemPppdEnv::new(
                    self.route_service.clone(),
                    self.addr_binding.clone(),
                ));
                let config_store: Arc<dyn PppdConfigStore> = Arc::new(SystemPppdConfigStore);

                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task_with_resource(
                    task_label::task::PPPD_RUN,
                    iface_name.clone(),
                    async move {
                        create_pppd_thread(
                            config.attach_iface_name,
                            config.iface_name,
                            config.pppd_config,
                            task_status,
                            env,
                            config_store,
                        )
                        .await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                // 契约:iface 缺失视为启动失败,拒绝持久化
                service_status.just_change_status(ServiceStatus::Staring);
                service_status.just_change_status(ServiceStatus::Failed);
            }
        } else {
            service_status.just_change_status(ServiceStatus::Disabled);
        }

        service_status
    }
}

/// Abstraction over writing/deleting the `/etc/ppp/peers/<ppp_iface>` config file,
/// so the service lifecycle can be exercised with a test double.
pub(crate) trait PppdConfigStore: Send + Sync {
    fn write(
        &self,
        conf: &PPPDConfig,
        attach_iface_name: &str,
        ppp_iface_name: &str,
    ) -> Result<(), ()>;
    fn delete(&self, conf: &PPPDConfig, ppp_iface_name: &str);
}

pub(crate) struct SystemPppdConfigStore;

impl PppdConfigStore for SystemPppdConfigStore {
    fn write(
        &self,
        conf: &PPPDConfig,
        attach_iface_name: &str,
        ppp_iface_name: &str,
    ) -> Result<(), ()> {
        conf.write_config(attach_iface_name, ppp_iface_name)
    }

    fn delete(&self, conf: &PPPDConfig, ppp_iface_name: &str) {
        conf.delete_config(ppp_iface_name);
    }
}

pub(crate) async fn create_pppd_thread(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: ServiceHandle,
    env: Arc<dyn PppdEnv>,
    config_store: Arc<dyn PppdConfigStore>,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    service_status.just_change_status(ServiceStatus::Running);

    let Ok(_) = config_store.write(&pppd_conf, &attach_iface_name, &ppp_iface_name) else {
        tracing::error!("pppd config write error");
        service_status.just_change_status(ServiceStatus::Failed);
        return;
    };
    tracing::info!("PPPD config written successfully");

    let as_router = pppd_conf.default_route;

    let graceful = run_pppd_supervisor(
        ppp_iface_name.clone(),
        as_router,
        service_status.clone(),
        env,
        PppdTimings::default(),
    )
    .await;

    tracing::info!("PPPD worker thread exited");
    config_store.delete(&pppd_conf, &ppp_iface_name);
    service_status.just_change_status(if !graceful {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Stop
    });
}

/// Start one pppd session on behalf of a WAN link service: builds the
/// system env / config store (private to this module) and drives
/// [`create_pppd_thread`].
pub(crate) async fn run_pppd_for_link(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_config: PPPDConfig,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
) {
    let env: Arc<dyn PppdEnv> = Arc::new(SystemPppdEnv::new(route_service, addr_binding));
    let config_store: Arc<dyn PppdConfigStore> = Arc::new(SystemPppdConfigStore);
    create_pppd_thread(
        attach_iface_name,
        ppp_iface_name,
        pppd_config,
        service_status,
        env,
        config_store,
    )
    .await
}

#[derive(Clone)]
pub struct PPPDServiceConfigManagerService {
    store: PPPDServiceRepository,
    service: ServiceManager<PPPDService>,
}

#[async_trait::async_trait]
impl ConfigStoreController for PPPDServiceConfigManagerService {
    type Id = String;
    type Config = PPPDServiceConfig;
    type Store = PPPDServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for PPPDServiceConfigManagerService {
    type H = PPPDService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl PPPDServiceConfigManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
    ) -> Self {
        let store = store_service.pppd_service_store();
        let server_starter = PPPDService::new(route_service, addr_binding);
        let service = ServiceManager::init(store.list().await.unwrap(), server_starter).await;

        Self { service, store }
    }

    pub async fn get_pppd_configs_by_attach_iface_name(
        &self,
        attach_name: String,
    ) -> Vec<PPPDServiceConfig> {
        self.store.get_pppd_configs_by_attach_iface_name(attach_name).await.unwrap()
    }

    pub async fn get_config_by_name(&self, iface_name: String) -> Option<PPPDServiceConfig> {
        self.find_by_id(iface_name).await.ok().flatten()
    }

    pub async fn delete_and_stop_pppd(
        &self,
        iface_name: String,
    ) -> Result<Option<ServiceStatus>, DbError> {
        self.delete_and_stop_service(iface_name).await
    }

    pub async fn delete_and_stop_pppds_by_attach_iface_name(&self, attach_name: String) {
        let configs = self.get_pppd_configs_by_attach_iface_name(attach_name).await;
        for each in configs {
            if let Err(error) = self.delete_and_stop_pppd(each.iface_name).await {
                tracing::warn!(%error, "deleting pppd service by attach iface failed");
            }
        }
    }
}
