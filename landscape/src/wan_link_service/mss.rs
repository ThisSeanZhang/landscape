use std::sync::Arc;

use landscape_common::dev::LandscapeInterface;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::RuntimeWanLinkMssConfig;
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;

pub(super) async fn run(
    iface: LandscapeInterface,
    config: RuntimeWanLinkMssConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn MssClampDataplane>,
) {
    let mss_clamp = match dataplane.attach(iface.index, config.clamp_size, iface.mac.is_some()) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {}: {err}", iface.name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}
