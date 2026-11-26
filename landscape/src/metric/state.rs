use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::ServiceStatus;

#[derive(Default)]
pub(super) struct MetricStatus {
    inner: ArcSwap<ServiceStatus>,
}

impl MetricStatus {
    pub fn current(&self) -> ServiceStatus {
        self.inner.load().as_ref().clone()
    }

    pub(super) fn set(&self, status: ServiceStatus) {
        if **self.inner.load() != status {
            tracing::debug!(?status, "metric service status changed");
            self.inner.store(Arc::new(status));
        }
    }
}
