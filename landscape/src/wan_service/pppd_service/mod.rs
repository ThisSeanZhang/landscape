mod env;
mod supervisor;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use landscape_common::service::ServiceStatus;
use landscape_common::service::WatchService;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::link::session::{SessionSignal, SessionState};
use landscape_common::wan_service::pppd::PPPDConfig;
use uuid::Uuid;

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

pub(crate) async fn create_pppd_thread(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: WatchService,
    env: Arc<dyn PppdEnv>,
    config_store: Arc<dyn PppdConfigStore>,
    session: SessionSignal,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    session.set(SessionState::Starting);
    service_status.just_change_status(ServiceStatus::Running);

    let Ok(_) = config_store.write(&pppd_conf, &attach_iface_name, &ppp_iface_name) else {
        tracing::error!("pppd config write error");
        service_status.just_change_status(ServiceStatus::Failed);
        session.set(SessionState::Failed);
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

/// Convenience entry used by the WAN link runtime: builds the production env
/// and config store, then runs the pppd session. `link_id` owns the WAN route
/// recorded by the session.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_pppd_session(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: WatchService,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    link_id: Uuid,
    session: SessionSignal,
) {
    let env: Arc<dyn PppdEnv> = Arc::new(SystemPppdEnv::new(route_service, addr_binding, link_id));
    let config_store: Arc<dyn PppdConfigStore> = Arc::new(SystemPppdConfigStore);

    create_pppd_thread(
        attach_iface_name,
        ppp_iface_name,
        pppd_conf,
        service_status,
        env,
        config_store,
        session,
    )
    .await;
}
