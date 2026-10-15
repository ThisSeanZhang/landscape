mod env;
mod supervisor;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::ServiceHandle;
use landscape_common::service::ServiceStatus;
use landscape_common::wan_link::{LinkStateHandle, V4Runtime, swap_if_changed};
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_ebpf::chain::wan_link::WanLinkDataplane;

use crate::sys_service::route::IpRouteService;

use env::{PppdEnv, PppdTimings, SystemPppdEnv};
use supervisor::run_pppd_supervisor;

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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_pppd_thread(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: ServiceHandle,
    env: Arc<dyn PppdEnv>,
    config_store: Arc<dyn PppdConfigStore>,
    session: Option<LinkStateHandle>,
    v4_runtime: Arc<ArcSwap<V4Runtime>>,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    service_status.just_change_status(ServiceStatus::Running);

    let Ok(_) = config_store.write(&pppd_conf, &attach_iface_name, &ppp_iface_name) else {
        tracing::error!("pppd config write error");
        swap_if_changed(&v4_runtime, V4Runtime::Stopped);
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
        session,
        v4_runtime.clone(),
    )
    .await;

    tracing::info!("PPPD worker thread exited");
    config_store.delete(&pppd_conf, &ppp_iface_name);
    swap_if_changed(&v4_runtime, V4Runtime::Stopped);
    service_status.just_change_status(if !graceful {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Stop
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pppd_for_link(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_config: PPPDConfig,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    chain_dataplane: Arc<WanLinkDataplane>,
    link_id: uuid::Uuid,
    chain_id: u16,
    session: Option<LinkStateHandle>,
    v4_runtime: Arc<ArcSwap<V4Runtime>>,
) {
    let env: Arc<dyn PppdEnv> =
        Arc::new(SystemPppdEnv::new(route_service, chain_dataplane, link_id, chain_id));
    let config_store: Arc<dyn PppdConfigStore> = Arc::new(SystemPppdConfigStore);
    create_pppd_thread(
        attach_iface_name,
        ppp_iface_name,
        pppd_config,
        service_status,
        env,
        config_store,
        session,
        v4_runtime,
    )
    .await
}
