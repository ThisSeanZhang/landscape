use landscape_common::concurrency::{spawn_task, task_label};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
#[allow(dead_code)]
pub struct LandscapeEbpfService {
    cancel: CancellationToken,
}

impl LandscapeEbpfService {
    pub fn new() -> Self {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        spawn_task(task_label::task::EBPF_NEIGH_UPDATE, async move {
            if let Err(e) = landscape_ebpf::base::ip_mac::neigh_update(cancel_clone).await {
                tracing::warn!("eBPF neigh_update service exited with error: {e}");
            }
        });

        LandscapeEbpfService { cancel }
    }

    pub async fn stop(&self) {
        self.cancel.cancel();
        tracing::info!("eBPF neigh_update service stop signal sent");
    }
}
