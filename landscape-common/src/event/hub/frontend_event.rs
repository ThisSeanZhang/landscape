use crate::observer::IfaceObserverAction;

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
