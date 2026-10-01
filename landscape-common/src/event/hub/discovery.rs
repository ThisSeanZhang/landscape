use std::net::IpAddr;

use tokio::sync::{broadcast, mpsc};

use crate::net::MacAddr;

/// How a device address was observed outside of the DHCP assignment flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanDiscoverySource {
    /// Periodic ARP scan of the LAN subnet (IPv4).
    Arp,
    /// IPv6 neighbor observation (reserved for future L3-only sources).
    Neighbor,
}

/// A passive MAC/IP observation feeding the LAN device directory. `mac` is
/// `None` for L3-only sources (e.g. TUN interfaces) where no link-layer
/// address can be observed.
#[derive(Debug, Clone)]
pub struct LanDiscoveryEvent {
    pub iface_name: String,
    pub mac: Option<MacAddr>,
    pub ip: IpAddr,
    pub source: LanDiscoverySource,
}

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LanDiscoveryEventSender {
    tx: mpsc::Sender<LanDiscoveryEvent>,
}

impl LanDiscoveryEventSender {
    pub(super) fn new(tx: mpsc::Sender<LanDiscoveryEvent>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: LanDiscoveryEvent,
    ) -> Result<(), mpsc::error::SendError<LanDiscoveryEvent>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: LanDiscoveryEvent,
    ) -> Result<(), mpsc::error::TrySendError<LanDiscoveryEvent>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct LanDiscoveryEventReader {
    rx: broadcast::Receiver<LanDiscoveryEvent>,
}

impl LanDiscoveryEventReader {
    pub fn new(rx: broadcast::Receiver<LanDiscoveryEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<LanDiscoveryEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
