use std::net::Ipv4Addr;

use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::net::MacAddr;

#[derive(Debug, Clone)]
pub struct IPv4AssignInfo {
    pub iface_name: String,
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub device_id: Option<Uuid>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub enum IPv4AssignEvent {
    Allocated(IPv4AssignInfo),
    Expired(IPv4AssignInfo),
}

#[derive(Clone)]
pub struct IPv4AssignEventSender {
    tx: mpsc::Sender<IPv4AssignEvent>,
}

impl IPv4AssignEventSender {
    pub fn new(tx: mpsc::Sender<IPv4AssignEvent>) -> Self {
        Self { tx }
    }

    pub fn try_send(
        &self,
        event: IPv4AssignEvent,
    ) -> Result<(), mpsc::error::TrySendError<IPv4AssignEvent>> {
        self.tx.try_send(event)
    }
}

pub struct IPv4AssignEventReader {
    rx: broadcast::Receiver<IPv4AssignEvent>,
}

impl IPv4AssignEventReader {
    pub fn new(rx: broadcast::Receiver<IPv4AssignEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<IPv4AssignEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
