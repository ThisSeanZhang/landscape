use tokio::sync::{broadcast, mpsc};

use crate::net::MacAddr;
use uuid::Uuid;

/// What materially changed on a directory entry. `last_active`-only
/// refreshes are silent — the directory only speaks up when an observable
/// field moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanDeviceChange {
    /// The IPv4 address or the IPv6 address set changed.
    Addresses,
    /// hostname / display_name / device_id changed, or the entry was
    /// created. (A dedicated `Created` variant can be added later for
    /// frontend push; consumers today treat it as "identity now exists".)
    Identity,
    /// The entry left the directory. Only anonymous GC removes entries:
    /// unenrollment keeps the entry and strips its identity instead
    /// (`Identity` events), so unenrolling never emits `Removed`.
    Removed,
}

/// A change notification emitted by the LAN device directory after the
/// change has been applied to the live tables. Minimal payload: consumers
/// that need the new state read it from the directory (point reads are
/// always fresh; read-after-event is guaranteed by the single-writer
/// apply-then-emit ordering).
///
/// Delivery is best-effort: if the fan-out channel runs dry of capacity the
/// event is dropped (logged). Consumers must tolerate gaps — periodic full
/// reconciliation (e.g. the DDNS sync interval) is the compensation path.
#[derive(Debug, Clone)]
pub struct LanDeviceEvent {
    pub entry_id: Uuid,
    pub mac: Option<MacAddr>,
    /// DDNS and per-device consumers only care about `Some`.
    pub device_id: Option<Uuid>,
    pub change: LanDeviceChange,
}

// ── Sender ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LanDeviceEventSender {
    tx: mpsc::Sender<LanDeviceEvent>,
}

impl LanDeviceEventSender {
    pub(super) fn new(tx: mpsc::Sender<LanDeviceEvent>) -> Self {
        Self { tx }
    }

    /// Direct construction for directory emission tests. Not intended for
    /// production use.
    #[doc(hidden)]
    pub fn new_for_test(tx: mpsc::Sender<LanDeviceEvent>) -> Self {
        Self { tx }
    }

    pub async fn send(
        &self,
        event: LanDeviceEvent,
    ) -> Result<(), mpsc::error::SendError<LanDeviceEvent>> {
        self.tx.send(event).await
    }

    pub fn try_send(
        &self,
        event: LanDeviceEvent,
    ) -> Result<(), mpsc::error::TrySendError<LanDeviceEvent>> {
        self.tx.try_send(event)
    }
}

// ── Reader ────────────────────────────────────────────────────

pub struct LanDeviceEventReader {
    rx: broadcast::Receiver<LanDeviceEvent>,
}

impl LanDeviceEventReader {
    pub fn new(rx: broadcast::Receiver<LanDeviceEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Result<LanDeviceEvent, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}
