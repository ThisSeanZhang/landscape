use std::net::Ipv6Addr;

use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::net::MacAddr;

#[derive(Debug, Clone)]
pub struct IPv6AssignInfo {
    pub iface_name: String,
    pub mac: MacAddr,
    pub ips: Vec<Ipv6Addr>,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub enum IPv6AssignEvent {
    Allocated(IPv6AssignInfo),
    Expired(IPv6AssignInfo),
    Flush(IPv6AssignInfo),
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

// ── IAPrefix Event ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum IAPrefixEvent {
    Updated { iface_name: String },
    Expired { iface_name: String },
}

#[derive(Clone)]
pub struct IAPrefixEventSender {
    tx: mpsc::Sender<IAPrefixEvent>,
}

impl IAPrefixEventSender {
    pub fn new(tx: mpsc::Sender<IAPrefixEvent>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: IAPrefixEvent,
    ) -> Result<(), mpsc::error::SendError<IAPrefixEvent>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: IAPrefixEvent,
    ) -> Result<(), mpsc::error::TrySendError<IAPrefixEvent>> {
        self.tx.try_send(event)
    }
}

pub struct IAPrefixEventReader {
    rx: broadcast::Receiver<IAPrefixEvent>,
}

impl IAPrefixEventReader {
    pub fn new(rx: broadcast::Receiver<IAPrefixEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<IAPrefixEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
