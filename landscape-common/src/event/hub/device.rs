use tokio::sync::{broadcast, mpsc};

use crate::config_service::enrolled_device::EnrolledDevice;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // 事件变体携带完整设备数据，属合理设计
pub enum EnrolledDeviceEvent {
    Updated { old: Option<EnrolledDevice>, new: EnrolledDevice },
    Deleted { old: EnrolledDevice },
}

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EnrolledDeviceEventSender {
    tx: mpsc::Sender<EnrolledDeviceEvent>,
}

impl EnrolledDeviceEventSender {
    pub(super) fn new(tx: mpsc::Sender<EnrolledDeviceEvent>) -> Self {
        Self { tx }
    }

    #[allow(clippy::result_large_err)] // tokio mpsc 错误类型内嵌整个事件，API 固有限制
    pub async fn send(
        &self,
        event: EnrolledDeviceEvent,
    ) -> Result<(), mpsc::error::SendError<EnrolledDeviceEvent>> {
        self.tx.send(event).await
    }

    #[allow(clippy::result_large_err)] // tokio mpsc 错误类型内嵌整个事件，API 固有限制
    pub fn try_send(
        &self,
        event: EnrolledDeviceEvent,
    ) -> Result<(), mpsc::error::TrySendError<EnrolledDeviceEvent>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct EnrolledDeviceEventReader {
    rx: broadcast::Receiver<EnrolledDeviceEvent>,
}

impl EnrolledDeviceEventReader {
    pub fn new(rx: broadcast::Receiver<EnrolledDeviceEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<EnrolledDeviceEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
