use tokio::sync::broadcast;

use super::iface::IfaceObserverAction;

#[derive(Clone, Debug)]
pub enum FrontendEvent {
    IfaceUp(String),
    IfaceDown(String),
}

impl From<IfaceObserverAction> for FrontendEvent {
    fn from(action: IfaceObserverAction) -> Self {
        match action {
            IfaceObserverAction::Up(name) => FrontendEvent::IfaceUp(name),
            IfaceObserverAction::Down(name) => FrontendEvent::IfaceDown(name),
        }
    }
}

pub struct FrontendEventReader {
    rx: broadcast::Receiver<FrontendEvent>,
}

impl FrontendEventReader {
    pub fn new(rx: broadcast::Receiver<FrontendEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<FrontendEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
