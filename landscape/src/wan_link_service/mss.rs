use std::sync::Arc;

use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkMssConfig, SessionIface};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;

pub(super) async fn run(
    iface: SessionIface,
    config: RuntimeWanLinkMssConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn MssClampDataplane>,
) {
    let mss_clamp = match dataplane.attach(iface.ifindex, config.clamp_size, iface.has_mac()) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {}: {err}", iface.iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}
