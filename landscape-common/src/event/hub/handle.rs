use tokio::sync::broadcast;

use super::frontend_event::FrontendEvent;
use super::iface::IfaceEventReader;
use crate::observer::IfaceObserverAction;

pub struct EventHubHandle {
    iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    // Keep the initial receivers alive so the broadcast channels always have at
    // least one active receiver. This prevents dispatcher events from being
    // dropped due to zero receivers before services subscribe.
    _broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
    _frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
}

impl EventHubHandle {
    pub(super) fn new(
        iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        iface_broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
        frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
    ) -> Self {
        Self {
            iface_broadcast_tx,
            frontend_broadcast_tx,
            _broadcast_rx: iface_broadcast_rx,
            _frontend_broadcast_rx: frontend_broadcast_rx,
        }
    }

    pub fn subscribe_iface(&self) -> IfaceEventReader {
        IfaceEventReader::new(self.iface_broadcast_tx.subscribe())
    }

    pub fn subscribe_frontend(&self) -> broadcast::Receiver<FrontendEvent> {
        self.frontend_broadcast_tx.subscribe()
    }
}
