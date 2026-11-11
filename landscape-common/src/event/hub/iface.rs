use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, PartialEq)]
pub enum IfaceObserverAction {
    /// Admin state changed to up (`IFF_UP`).
    Up(String),
    /// Admin state changed to down, or the link was deleted.
    ///
    /// Cable removal does not produce this event.
    Down(String),
    /// Cable insertion detected on an interface that was already admin-up.
    CarrierUp(String),
}

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
