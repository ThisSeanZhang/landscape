use std::collections::HashMap;
use std::mem::discriminant;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use landscape_common::service::manager::{RestartError, ServiceManager, ServiceStarterTrait};
use landscape_common::wan_link::WanLinkConfig;
use tokio::sync::watch;
use uuid::Uuid;

/// A running instance only receives configs for the WAN kind it started with.
/// While the service manager drains it, saves replace the config for the next start.
pub(super) struct LinkConfigUpdates {
    active: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>>,
    pending: Mutex<HashMap<Uuid, WanLinkConfig>>,
}

impl LinkConfigUpdates {
    pub(super) fn new(active: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>>) -> Self {
        Self { active, pending: Mutex::new(HashMap::new()) }
    }

    pub(super) async fn deliver<H: ServiceStarterTrait<Config = WanLinkConfig>>(
        &self,
        manager: &ServiceManager<H>,
        config: &WanLinkConfig,
        timeout: Duration,
    ) {
        // Reconnect the manager to its queue even if this save coalesces with
        // a restart admitted on an earlier runtime.
        let restart = manager.restart_existing(config.clone(), timeout);
        if !self.queue(config) {
            return;
        }
        match restart.await {
            Ok(()) => {}
            Err(RestartError::Closed) => {
                // New link or lost consumer. The save holds the WAN config gate until
                // admission finishes, so deletion cannot race this create/update.
                manager.deliver_bounded(config.clone(), timeout).await;
            }
            Err(RestartError::TimedOut) => {
                tracing::warn!(id = %config.id, "restart queue full; queued start will read the latest WAN config");
            }
        }
    }

    /// Returns true when the service manager needs to start a new instance.
    pub(super) fn queue(&self, config: &WanLinkConfig) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if let Some(next) = pending.get_mut(&config.id) {
            if config.update_at > next.update_at {
                *next = config.clone();
            }
            return false;
        }

        let mut active = self.active.lock().unwrap();
        if let Some(tx) = active.get(&config.id) {
            let current = tx.borrow();
            if config.update_at < current.update_at {
                return false;
            }
            let same_kind = discriminant(&current.kind) == discriminant(&config.kind);
            drop(current);
            if same_kind && tx.send(config.clone()).is_ok() {
                return false;
            }
        }
        active.remove(&config.id);
        pending.insert(config.id, config.clone());
        true
    }

    pub(super) fn start(
        &self,
        queued: WanLinkConfig,
    ) -> (WanLinkConfig, watch::Sender<WanLinkConfig>) {
        let mut pending = self.pending.lock().unwrap();
        let latest = pending.remove(&queued.id).unwrap_or(queued);
        // The starter subscribes only once the dataplane is ready. A save during
        // setup therefore queues a replacement, even if this setup ultimately fails.
        let (tx, _) = watch::channel(latest.clone());
        self.active.lock().unwrap().insert(latest.id, tx.clone());
        (latest, tx)
    }

    pub(super) fn remove(&self, id: Uuid) {
        let mut pending = self.pending.lock().unwrap();
        pending.remove(&id);
        self.active.lock().unwrap().remove(&id);
    }
}
