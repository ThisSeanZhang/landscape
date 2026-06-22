mod device;
mod frontend_event;
mod handle;
mod iface;

pub use device::{EnrolledDeviceEvent, EnrolledDeviceEventReader, EnrolledDeviceEventSender};
pub use frontend_event::FrontendEvent;
pub use handle::EventHubHandle;
pub use iface::{IfaceEventReader, IfaceEventSender};

use tokio::sync::{broadcast, mpsc};

use crate::observer::IfaceObserverAction;

const IFACE_MPSC_CAPACITY: usize = 32;
const IFACE_BROADCAST_CAPACITY: usize = 64;
const FRONTEND_BROADCAST_CAPACITY: usize = 256;
const DEVICE_MPSC_CAPACITY: usize = 32;
const DEVICE_BROADCAST_CAPACITY: usize = 64;

pub struct EventHub {
    rx: mpsc::Receiver<IfaceObserverAction>,
    broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    broadcast_rx: broadcast::Receiver<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    frontend_broadcast_rx: broadcast::Receiver<FrontendEvent>,
    mpsc_tx: mpsc::Sender<IfaceObserverAction>,

    device_rx: mpsc::Receiver<EnrolledDeviceEvent>,
    device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
    device_broadcast_rx: broadcast::Receiver<EnrolledDeviceEvent>,
    device_mpsc_tx: mpsc::Sender<EnrolledDeviceEvent>,
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(IFACE_MPSC_CAPACITY);
        let (broadcast_tx, broadcast_rx) = broadcast::channel(IFACE_BROADCAST_CAPACITY);
        let (frontend_broadcast_tx, frontend_broadcast_rx) =
            broadcast::channel(FRONTEND_BROADCAST_CAPACITY);

        let (device_tx, device_rx) = mpsc::channel(DEVICE_MPSC_CAPACITY);
        let (device_broadcast_tx, device_broadcast_rx) =
            broadcast::channel(DEVICE_BROADCAST_CAPACITY);

        Self {
            rx,
            broadcast_tx,
            broadcast_rx,
            frontend_broadcast_tx,
            frontend_broadcast_rx,
            mpsc_tx: tx,

            device_rx,
            device_broadcast_tx,
            device_broadcast_rx,
            device_mpsc_tx: device_tx,
        }
    }

    pub fn iface_sender(&self) -> IfaceEventSender {
        IfaceEventSender::new(self.mpsc_tx.clone())
    }

    pub fn enrolled_device_sender(&self) -> EnrolledDeviceEventSender {
        EnrolledDeviceEventSender::new(self.device_mpsc_tx.clone())
    }

    pub fn spawn(self) -> EventHubHandle {
        let Self {
            rx,
            broadcast_tx,
            broadcast_rx,
            frontend_broadcast_tx,
            frontend_broadcast_rx,
            mpsc_tx: _,

            device_rx,
            device_broadcast_tx,
            device_broadcast_rx,
            device_mpsc_tx: _,
        } = self;

        let handle = EventHubHandle::new(
            broadcast_tx.clone(),
            broadcast_rx,
            frontend_broadcast_tx.clone(),
            frontend_broadcast_rx,
            device_broadcast_tx.clone(),
            device_broadcast_rx,
        );
        crate::concurrency::spawn_task(
            crate::concurrency::task_label::task::EVENT_HUB_DISPATCHER,
            async move {
                Self::run_dispatcher(
                    rx,
                    broadcast_tx,
                    frontend_broadcast_tx,
                    device_rx,
                    device_broadcast_tx,
                )
                .await
            },
        );
        handle
    }

    async fn run_dispatcher(
        mut rx: mpsc::Receiver<IfaceObserverAction>,
        broadcast_tx: broadcast::Sender<IfaceObserverAction>,
        frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
        mut device_rx: mpsc::Receiver<EnrolledDeviceEvent>,
        device_broadcast_tx: broadcast::Sender<EnrolledDeviceEvent>,
    ) {
        loop {
            tokio::select! {
                Some(event) = rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch Iface event");
                    if let Err(e) = broadcast_tx.send(event.clone()) {
                        tracing::warn!("EventHub: iface broadcast channel full, dropping event: {e:?}");
                    }
                    if let Err(e) = frontend_broadcast_tx.send(FrontendEvent::from(event)) {
                        tracing::warn!("EventHub: frontend broadcast channel full, dropping event: {e:?}");
                    }
                }
                Some(event) = device_rx.recv() => {
                    tracing::debug!(?event, "EventHub: dispatch Device event");
                    if let Err(e) = device_broadcast_tx.send(event) {
                        tracing::warn!("EventHub: device broadcast channel full, dropping event: {e:?}");
                    }
                }
                else => break,
            }
        }
        tracing::info!("EventHub dispatcher task stopped");
    }
}
