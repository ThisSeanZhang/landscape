use tokio::sync::broadcast;

use super::device::EnrolledDeviceEvent;
use super::frontend_event::FrontendEvent;
use super::iface::IfaceEventReader;
use crate::observer::IfaceObserverAction;

pub struct EventHubHandle {
    iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
    // Keep the initial receivers alive so the broadcast channels always have at
    // least one active receiver. This prevents dispatcher events from being
    // dropped due to zero receivers before services subscribe.
    _broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
    _frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
    _device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
}

impl EventHubHandle {
    pub(super) fn new(
        iface_broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        iface_broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
        frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
        device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
        device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
    ) -> Self {
        Self {
            iface_broadcast_tx,
            frontend_broadcast_tx,
            device_broadcast_tx,
            _broadcast_rx: iface_broadcast_rx,
            _frontend_broadcast_rx: frontend_broadcast_rx,
            _device_broadcast_rx: device_broadcast_rx,
        }
    }

    pub fn subscribe_iface(&self) -> IfaceEventReader {
        IfaceEventReader::new(self.iface_broadcast_tx.subscribe())
    }

    pub fn subscribe_frontend(&self) -> broadcast::Receiver<FrontendEvent> {
        self.frontend_broadcast_tx.subscribe()
    }

    pub fn subscribe_device(&self) -> broadcast::Receiver<EnrolledDeviceEvent> {
        self.device_broadcast_tx.subscribe()
    }
}
