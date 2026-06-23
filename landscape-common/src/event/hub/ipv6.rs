use std::net::Ipv6Addr;

use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::net::MacAddr;

#[derive(Debug, Clone)]
pub struct IPv6AssignInfo {
    pub iface_name: String,
    pub mac: MacAddr,
    pub ip: Ipv6Addr,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub enum IPv6AssignEvent {
    Allocated(IPv6AssignInfo),
    Expired(IPv6AssignInfo),
}

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IPv6AssignEventSender {
    tx: mpsc::Sender<IPv6AssignEvent>,
}

impl IPv6AssignEventSender {
    pub fn new(tx: mpsc::Sender<IPv6AssignEvent>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: IPv6AssignEvent,
    ) -> Result<(), mpsc::error::SendError<IPv6AssignEvent>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: IPv6AssignEvent,
    ) -> Result<(), mpsc::error::TrySendError<IPv6AssignEvent>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct IPv6AssignEventReader {
    rx: broadcast::Receiver<IPv6AssignEvent>,
}

impl IPv6AssignEventReader {
    pub fn new(rx: broadcast::Receiver<IPv6AssignEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<IPv6AssignEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
