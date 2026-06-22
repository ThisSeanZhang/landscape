use tokio::sync::mpsc;

use crate::observer::IfaceObserverAction;

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
