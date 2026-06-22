mod frontend_event;
mod handle;
mod iface_sender;

pub use frontend_event::FrontendEvent;
pub use handle::EventHubHandle;
pub use iface_sender::IfaceEventSender;

use tokio::sync::{broadcast, mpsc};

use crate::observer::IfaceObserverAction;

const IFACE_MPSC_CAPACITY: usize = 32;
const IFACE_BROADCAST_CAPACITY: usize = 64;
const FRONTEND_BROADCAST_CAPACITY: usize = 256;

pub struct EventHub {
    rx: mpsc::Receiver<IfaceObserverAction>,
    broadcast_tx: broadcast::Sender<IfaceObserverAction>,
    frontend_broadcast_tx: broadcast::Sender<FrontendEvent>,
    mpsc_tx: mpsc::Sender<IfaceObserverAction>,
}

impl EventHub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(IFACE_MPSC_CAPACITY);
        let (broadcast_tx, _) = broadcast::channel(IFACE_BROADCAST_CAPACITY);
        let (frontend_broadcast_tx, _) = broadcast::channel(FRONTEND_BROADCAST_CAPACITY);
        Self {
            rx,
            broadcast_tx,
            frontend_broadcast_tx,
            mpsc_tx: tx,
        }
    }

    pub fn iface_sender(&self) -> IfaceEventSender {
        IfaceEventSender::new(self.mpsc_tx.clone())
    }

    pub fn spawn(self) -> EventHubHandle {
        let handle =
            EventHubHandle::new(self.broadcast_tx.clone(), self.frontend_broadcast_tx.clone());
        tokio::spawn(async move { self.run_router().await });
        handle
    }

    async fn run_router(mut self) {
        while let Some(event) = self.rx.recv().await {
            tracing::debug!(?event, "EventHub: dispatch Iface event");
            let _ = self.broadcast_tx.send(event.clone());
            let _ = self.frontend_broadcast_tx.send(FrontendEvent::from(event));
        }
        tracing::info!("EventHub router task stopped");
    }
}
