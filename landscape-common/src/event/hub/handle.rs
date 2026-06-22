use tokio::sync::broadcast;

use super::frontend_event::FrontendEvent;
use crate::observer::IfaceObserverAction;

#[derive(Clone)]
pub struct EventHubHandle {
    iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
}

impl EventHubHandle {
    pub(super) fn new(
        iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    ) -> Self {
        Self { iface_broadcast_tx, frontend_broadcast_tx }
    }

    pub fn subscribe_iface(&self) -> broadcast::Receiver<IfaceObserverAction> {
        self.iface_broadcast_tx.subscribe()
    }

    pub fn subscribe_frontend(&self) -> broadcast::Receiver<FrontendEvent> {
        self.frontend_broadcast_tx.subscribe()
    }
}
