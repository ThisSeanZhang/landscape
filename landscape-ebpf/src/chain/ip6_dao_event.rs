use arc_swap::ArcSwapOption;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::net::MacAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use zerocopy::FromBytes;

use crate::metric::{dup_epoll_async_fd, run_ringbuf_loop};
use crate::MAP_PATHS;

/// A DAD NS target learned by the per-iface `tc_lan_dao` data path.
/// Wire layout must match `struct ip6_dao_event` in bpf/neigh_ip6_event.h;
/// the explicit pad keeps both sides at the same size without relying on
/// implicit tail padding.
#[derive(Debug, Clone, Copy, zerocopy::FromBytes)]
#[repr(C)]
pub struct Ip6DaoEvent {
    pub ifindex: u32,
    pub ip: [u8; 16],
    pub mac: [u8; 6],
    pub __pad: [u8; 6],
}

impl Ip6DaoEvent {
    fn try_from_wire(data: &[u8]) -> Result<Self, String> {
        Ip6DaoEvent::read_from_bytes(data)
            .map_err(|e| format!("unexpected ip6_dao_event wire bytes: {e:?}"))
    }

    /// The DAD NS target, network byte order.
    pub fn ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.ip)
    }

    /// The sender's link-layer address (Ethernet source MAC of the NS frame).
    pub fn mac_addr(&self) -> MacAddr {
        MacAddr::from(self.mac)
    }
}

/// Event source that consumes the globally shared `ip6_dao_events` ringbuf and
/// forwards decoded events through the channel attached via
/// [`Ip6DaoEventSource::attach_channel`]. Exactly one instance should exist
/// process-wide; per-iface dispatch is left to the service side. A supervisor
/// holding this source re-attaches a fresh channel whenever the downstream
/// dispatcher task dies, and rebuilds the ringbuf consumer when its task exits
/// unexpectedly, so DAD learning self-heals instead of silently going dark.
pub struct Ip6DaoEventSource {
    cancel: CancellationToken,
    tx_slot: Arc<ArcSwapOption<mpsc::Sender<Ip6DaoEvent>>>,
    /// Fired when the current ringbuf consumer task exits.
    died: std::sync::Mutex<CancellationToken>,
}

impl Ip6DaoEventSource {
    /// Starts the process-wide ringbuf consumer. Events are dropped until a
    /// channel is attached via [`Self::attach_channel`].
    pub fn spawn() -> Result<Self, String> {
        let tx_slot = Arc::new(ArcSwapOption::<mpsc::Sender<Ip6DaoEvent>>::new(None));
        let cancel = CancellationToken::new();
        let died = CancellationToken::new();
        Self::spawn_consumer_loop(tx_slot.clone(), cancel.clone(), died.clone())?;
        Ok(Ip6DaoEventSource { cancel, tx_slot, died: std::sync::Mutex::new(died) })
    }

    /// Opens the pinned `ip6_dao_events` ringbuf and spawns the consumption
    /// loop, firing `died` on any exit so the supervisor can rebuild it.
    fn spawn_consumer_loop(
        tx_slot: Arc<ArcSwapOption<mpsc::Sender<Ip6DaoEvent>>>,
        cancel: CancellationToken,
        died: CancellationToken,
    ) -> Result<(), String> {
        let map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.ip6_dao_events)
            .map_err(|e| format!("failed to open pinned ip6_dao_events map: {e}"))?;
        let tx_slot_cb = tx_slot.clone();
        let callback = move |data: &[u8]| -> i32 {
            let event = match Ip6DaoEvent::try_from_wire(data) {
                Ok(ev) => ev,
                Err(e) => {
                    tracing::warn!("{e}; dropping ip6_dao_event");
                    return 0;
                }
            };
            if let Some(tx) = tx_slot_cb.load().as_ref() {
                match tx.try_send(event) {
                    Err(TrySendError::Closed(_)) => {
                        // The attached dispatcher channel is gone; the
                        // supervisor is expected to re-attach shortly.
                        tracing::warn!("ip6_dao_event channel closed; event dropped");
                    }
                    Err(TrySendError::Full(_)) => {
                        // Bounded best-effort: the dispatcher is
                        // backpressured, drop rather than grow.
                    }
                    Ok(_) => {}
                }
            }
            0
        };

        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(&map, callback)
            .map_err(|e| format!("failed to add ip6_dao_events ringbuf: {e}"))?;
        let ringbuf =
            builder.build().map_err(|e| format!("failed to build ip6_dao_events ringbuf: {e}"))?;
        let async_fd = dup_epoll_async_fd(ringbuf.epoll_fd())?;

        let consumer = spawn_task(
            task_label::task::EBPF_IP6_DAO_EVENT_SOURCE,
            run_ringbuf_loop(ringbuf, async_fd, cancel),
        );
        tokio::spawn(async move {
            match consumer.await {
                Ok(()) => tracing::warn!("ip6_dao_event ringbuf consumer stopped"),
                Err(join) => tracing::error!("ip6_dao_event ringbuf consumer panicked: {join}"),
            }
            died.cancel();
        });
        Ok(())
    }

    /// Redirects the event flow to a new channel; the ringbuf consumer keeps
    /// running and all following events go through `tx`. Used by the supervisor
    /// to restart a dead dispatcher without recreating the ringbuf consumer.
    pub fn attach_channel(&self, tx: mpsc::Sender<Ip6DaoEvent>) {
        self.tx_slot.store(Some(Arc::new(tx)));
    }

    /// Cancellation token observed by the supervisor to shut down cleanly when
    /// the owning service is dropped.
    pub fn cancelled(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Token fired when the current ringbuf consumer task exits for any reason.
    pub fn consumer_died_token(&self) -> CancellationToken {
        self.died.lock().unwrap().clone()
    }

    /// Rebuilds the ringbuf consumption loop after an unexpected exit.
    pub fn restart_consumer(&self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            return Ok(());
        }
        let died = CancellationToken::new();
        Self::spawn_consumer_loop(self.tx_slot.clone(), self.cancel.clone(), died.clone())?;
        *self.died.lock().unwrap() = died;
        Ok(())
    }

    /// Signals the ringbuf consumer loop to exit (idempotent). Normally the
    /// consumer is stopped implicitly when the last reference to the source is
    /// dropped ([`Drop`]); this is the explicit equivalent.
    pub fn request_stop(&self) {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::info!("ip6_dao_event source stop requested from:\n{backtrace}");
        self.cancel.cancel();
    }

    #[cfg(test)]
    pub(crate) fn test_new(
        cancel: CancellationToken,
        tx_slot: Arc<ArcSwapOption<mpsc::Sender<Ip6DaoEvent>>>,
    ) -> Self {
        Ip6DaoEventSource {
            cancel,
            tx_slot,
            died: std::sync::Mutex::new(CancellationToken::new()),
        }
    }
}

impl Drop for Ip6DaoEventSource {
    fn drop(&mut self) {
        tracing::info!("ip6_dao_event source dropped; cancelling ringbuf consumer");
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod tc_lan_dao_skel {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_dao.skel.rs"));
    }

    #[test]
    fn wire_layout_matches_bpf_struct() {
        use std::mem::{offset_of, size_of};
        assert_eq!(
            size_of::<Ip6DaoEvent>(),
            size_of::<tc_lan_dao_skel::types::ip6_dao_event>(),
            "wire size must match bpf ip6_dao_event"
        );
        assert_eq!(
            offset_of!(Ip6DaoEvent, ifindex),
            offset_of!(tc_lan_dao_skel::types::ip6_dao_event, ifindex)
        );
        assert_eq!(
            offset_of!(Ip6DaoEvent, ip),
            offset_of!(tc_lan_dao_skel::types::ip6_dao_event, ip)
        );
        assert_eq!(
            offset_of!(Ip6DaoEvent, mac),
            offset_of!(tc_lan_dao_skel::types::ip6_dao_event, mac)
        );
        assert_eq!(
            offset_of!(Ip6DaoEvent, __pad),
            offset_of!(tc_lan_dao_skel::types::ip6_dao_event, __pad)
        );
    }

    #[test]
    fn try_from_wire_roundtrip() {
        let mut bytes = [0u8; size_of::<Ip6DaoEvent>()];
        bytes[0..4].copy_from_slice(&7u32.to_le_bytes());
        bytes[4..20].copy_from_slice(&[0xfd; 16]);
        bytes[20..26].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        bytes[26..32].copy_from_slice(&[0xab; 6]);

        let ev = Ip6DaoEvent::try_from_wire(&bytes).expect("decode wire bytes");
        assert_eq!(ev.ifindex, 7);
        assert_eq!(ev.ip, [0xfd; 16]);
        assert_eq!(ev.mac, [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(ev.__pad, [0xab; 6]);
    }

    #[test]
    fn try_from_wire_rejects_wrong_size() {
        assert!(Ip6DaoEvent::try_from_wire(&[0u8; size_of::<Ip6DaoEvent>() - 1]).is_err());
        assert!(Ip6DaoEvent::try_from_wire(&[0u8; size_of::<Ip6DaoEvent>() + 1]).is_err());
    }
}
