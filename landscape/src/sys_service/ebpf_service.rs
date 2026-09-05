use tokio_util::sync::CancellationToken;

#[derive(Clone)]
#[allow(dead_code)]
pub struct LandscapeEbpfService {
    cancel: CancellationToken,
}

impl LandscapeEbpfService {
    /// `cancel` comes from [`landscape_ebpf::runtime::EbpfRuntime::start_neigh_update`],
    /// which owns the ringbuf consumer task.
    pub fn new(cancel: CancellationToken) -> Self {
        LandscapeEbpfService { cancel }
    }

    pub async fn stop(&self) {
        self.cancel.cancel();
        tracing::info!("eBPF neigh_update service stop signal sent");
    }
}
