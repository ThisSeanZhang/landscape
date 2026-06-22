#[derive(Debug, Clone, PartialEq)]
pub enum IfaceObserverAction {
    Up(String),
    Down(String),
}
