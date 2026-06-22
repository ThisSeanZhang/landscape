use tokio::sync::{broadcast, mpsc};

use crate::observer::IfaceObserverAction;

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IfaceEventSender {
    tx: mpsc::Sender<IfaceObserverAction>,
}

impl IfaceEventSender {
    pub(super) fn new(tx: mpsc::Sender<IfaceObserverAction>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: IfaceObserverAction,
    ) -> Result<(), mpsc::error::SendError<IfaceObserverAction>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: IfaceObserverAction,
    ) -> Result<(), mpsc::error::TrySendError<IfaceObserverAction>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct IfaceEventReader {
    rx: broadcast::Receiver<IfaceObserverAction>,
}

impl IfaceEventReader {
    pub(super) fn new(rx: broadcast::Receiver<IfaceObserverAction>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<IfaceObserverAction, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
