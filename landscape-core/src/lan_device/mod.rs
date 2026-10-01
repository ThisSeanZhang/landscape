//! LAN device directory: a single-writer projection that folds device
//! identity (enrolled devices), address assignments (DHCPv4/v6, SLAAC) and
//! passive discovery (ARP scan) into one read-heavy view of "what devices
//! are on my LAN and which addresses do they hold".
//!
//! Layout:
//! * live tables — `DashMap` indexes, mutated only by the projection task
//!   ([`writer`], O(1) per event; point reads are always fresh)
//! * derived snapshot — an immutable [`DirectorySnapshot`] swapped in behind
//!   an `ArcSwap` after a short debounce, giving bulk consumers a consistent
//!   cut of the live tables
//!
//! Entity resolution: MAC is the strong anchor. Events without a MAC fall
//! back to an IP anchor; when a MAC-anchored entry later claims the same IP,
//! the address simply moves over (the strong anchor absorbs it). Address
//! ownership follows evidence strength — `Static > Lease > Arp` for IPv4,
//! `Static > Dhcpv6 > Slaac` for IPv6 — a weaker claim never displaces a
//! stronger owner, ties go to the latest claim. Anonymous entries (no
//! `device_id`) are garbage-collected after a TTL; enrolled entries stay for
//! the process lifetime.

mod entry;
mod snapshot;
mod writer;

pub use entry::{AddressSourceV4, AddressSourceV6, ArpPresence, DhcpLeaseTimes, LanDeviceEntry};
pub use snapshot::DirectorySnapshot;

#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use landscape_common::LAND_ARP_SCAN_INTERVAL;
use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IPv4AssignEventReader, IPv6AssignEvent,
    IPv6AssignEventReader, LanDeviceEventSender, LanDiscoveryEventReader,
};
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::{concurrency, concurrency::task_label};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

/// Debounce window folding event bursts (PD prefix Flush storms, full-subnet
/// ARP scans) into a single snapshot rebuild.
const SNAPSHOT_DEBOUNCE_MS: u64 = 150;
/// Periodic sweep removing stale anonymous entries.
const GC_INTERVAL_SECS: u64 = 60;
/// Entries without a `device_id` are dropped after being idle this long.
pub(super) const ANONYMOUS_TTL_SECS: f64 = 24.0 * 3600.0;
/// [`ANONYMOUS_TTL_SECS`] on the millisecond clock the entries use.
pub(super) const ANONYMOUS_TTL_MS: f64 = ANONYMOUS_TTL_SECS * 1000.0;
/// How long the current `device_id` holder must be idle before a runtime
/// identity claim (a DHCP-carried device_id) may re-anchor it to a newly
/// observed entry. Identity semantics — deliberately independent of
/// [`ANONYMOUS_TTL_SECS`] (GC semantics). Enrollment events are NOT gated
/// by this: the user's explicit binding re-anchors immediately.
pub(super) const DEVICE_ID_REANCHOR_IDLE_SECS: f64 = 600.0;
/// [`DEVICE_ID_REANCHOR_IDLE_SECS`] on the millisecond clock the entries use.
pub(super) const DEVICE_ID_REANCHOR_IDLE_MS: f64 = DEVICE_ID_REANCHOR_IDLE_SECS * 1000.0;
/// `last_active` freshness window for the `online` heuristic: two ARP scan
/// intervals (debug 10 min, release 2 h) so periodic-scan-only devices do
/// not flap offline between rounds. Active leases and server-tracked
/// DHCPv6 addresses keep a device online independent of this window;
/// SLAAC alone does not (a prefix Flush empties the set before devices
/// re-register) and neither does a lingering ARP-observed IPv4.
pub(super) const ONLINE_WINDOW_MS: f64 = (LAND_ARP_SCAN_INTERVAL * 2) as f64;

pub struct LanDeviceDirectory {
    // ── Live tables: written only by the projection task (see writer.rs) ──
    pub(super) entries: DashMap<Uuid, Arc<LanDeviceEntry>>,
    pub(super) by_mac: DashMap<MacAddr, Uuid>,
    pub(super) by_ipv4: DashMap<Ipv4Addr, Uuid>,
    pub(super) by_ipv6: DashMap<Ipv6Addr, Uuid>,
    pub(super) by_device_id: DashMap<Uuid, Uuid>,
    /// punycode hostname -> entry (enrolled priority adjudicated on write).
    pub(super) by_hostname: DashMap<String, Uuid>,

    // ── Derived read view ────────────────────────────────────────────────
    snapshot: ArcSwap<DirectorySnapshot>,
    watch_tx: watch::Sender<()>,
    /// Change-notification outlet (EventHub `lan_device` domain). Emissions
    /// happen strictly after the change is applied to the live tables
    /// (single-writer apply-then-emit), so read-after-event is consistent.
    pub(super) event_sender: Option<LanDeviceEventSender>,
}

impl LanDeviceDirectory {
    pub fn new(
        initial_devices: Vec<EnrolledDevice>,
        event_sender: LanDeviceEventSender,
        device_reader: EnrolledDeviceEventReader,
        ipv4_reader: IPv4AssignEventReader,
        ipv6_reader: IPv6AssignEventReader,
        discovery_reader: LanDiscoveryEventReader,
    ) -> Arc<Self> {
        let directory = Self::with_seed(&initial_devices, Some(event_sender));
        directory.spawn_projection(device_reader, ipv4_reader, ipv6_reader, discovery_reader);
        directory
    }

    fn with_seed(
        initial_devices: &[EnrolledDevice],
        event_sender: Option<LanDeviceEventSender>,
    ) -> Arc<Self> {
        let (watch_tx, _watch_rx) = watch::channel(());
        let directory = Arc::new(Self {
            entries: DashMap::new(),
            by_mac: DashMap::new(),
            by_ipv4: DashMap::new(),
            by_ipv6: DashMap::new(),
            by_device_id: DashMap::new(),
            by_hostname: DashMap::new(),
            snapshot: ArcSwap::from_pointee(DirectorySnapshot::default()),
            watch_tx,
            event_sender,
        });
        for device in initial_devices {
            directory.apply_device_event(EnrolledDeviceEvent::Updated {
                old: None,
                new: device.clone(),
            });
        }
        directory.rebuild_snapshot();
        directory
    }

    fn spawn_projection(
        self: &Arc<Self>,
        device_reader: EnrolledDeviceEventReader,
        ipv4_reader: IPv4AssignEventReader,
        ipv6_reader: IPv6AssignEventReader,
        discovery_reader: LanDiscoveryEventReader,
    ) {
        let directory = self.clone();
        concurrency::spawn_task(task_label::task::LAN_DEVICE_DIRECTORY, async move {
            use tokio::sync::broadcast::error::RecvError;
            use tokio::time::interval;

            let mut device_reader = device_reader;
            let mut ipv4_reader = ipv4_reader;
            let mut ipv6_reader = ipv6_reader;
            let mut discovery_reader = discovery_reader;
            let mut device_alive = true;
            let mut ipv4_alive = true;
            let mut ipv6_alive = true;
            let mut discovery_alive = true;

            let mut dirty = false;
            let mut debounce = interval(Duration::from_millis(SNAPSHOT_DEBOUNCE_MS));
            debounce.set_missed_tick_behavior(MissedTickBehavior::Skip);
            debounce.tick().await; // the first tick completes immediately
            let mut gc = interval(Duration::from_secs(GC_INTERVAL_SECS));
            gc.set_missed_tick_behavior(MissedTickBehavior::Delay);
            gc.tick().await;

            loop {
                if !device_alive && !ipv4_alive && !ipv6_alive && !discovery_alive {
                    break;
                }
                tokio::select! {
                    result = device_reader.recv(), if device_alive => match result {
                        Ok(event) => { directory.apply_device_event(event); dirty = true; }
                        Err(RecvError::Lagged(n)) => tracing::warn!("lan_device: device event lagged by {n}"),
                        Err(RecvError::Closed) => device_alive = false,
                    },
                    result = ipv4_reader.recv(), if ipv4_alive => match result {
                        Ok(event) => { directory.apply_ipv4_event(event); dirty = true; }
                        Err(RecvError::Lagged(n)) => tracing::warn!("lan_device: ipv4 event lagged by {n}"),
                        Err(RecvError::Closed) => ipv4_alive = false,
                    },
                    result = ipv6_reader.recv(), if ipv6_alive => match result {
                        Ok(event) => { directory.apply_ipv6_event(event); dirty = true; }
                        Err(RecvError::Lagged(n)) => tracing::warn!("lan_device: ipv6 event lagged by {n}"),
                        Err(RecvError::Closed) => ipv6_alive = false,
                    },
                    result = discovery_reader.recv(), if discovery_alive => match result {
                        Ok(event) => { directory.apply_discovery_event(event); dirty = true; }
                        Err(RecvError::Lagged(n)) => tracing::warn!("lan_device: discovery event lagged by {n}"),
                        Err(RecvError::Closed) => discovery_alive = false,
                    },
                    _ = debounce.tick() => {
                        if dirty {
                            directory.rebuild_snapshot();
                            dirty = false;
                        }
                    }
                    _ = gc.tick() => {
                        if directory.sweep_expired(get_f64_timestamp()) {
                            dirty = true;
                        }
                    }
                }
            }
            tracing::info!("lan_device: all event sources closed, projection task stopped");
        });
    }

    // ── Read API ──────────────────────────────────────────────────────────

    /// Latest derived snapshot (may trail the live tables by up to one
    /// debounce window).
    pub fn snapshot(&self) -> Arc<DirectorySnapshot> {
        self.snapshot.load_full()
    }

    /// Dirty-signal subscription for bulk consumers: coalesced, latest-value
    /// semantics. On wake-up, call [`Self::snapshot`].
    pub fn subscribe_watch(&self) -> watch::Receiver<()> {
        self.watch_tx.subscribe()
    }

    pub fn entry_by_mac(&self, mac: &MacAddr) -> Option<Arc<LanDeviceEntry>> {
        let id = *self.by_mac.get(mac)?;
        Some(self.entries.get(&id)?.value().clone())
    }

    pub fn entry_by_ipv4(&self, ip: &Ipv4Addr) -> Option<Arc<LanDeviceEntry>> {
        let id = *self.by_ipv4.get(ip)?;
        Some(self.entries.get(&id)?.value().clone())
    }

    pub fn entry_by_ipv6(&self, ip: &Ipv6Addr) -> Option<Arc<LanDeviceEntry>> {
        let id = *self.by_ipv6.get(ip)?;
        Some(self.entries.get(&id)?.value().clone())
    }

    pub fn entry_by_device_id(&self, device_id: &Uuid) -> Option<Arc<LanDeviceEntry>> {
        let id = *self.by_device_id.get(device_id)?;
        Some(self.entries.get(&id)?.value().clone())
    }

    /// Hostname lookup; accepts either plain or punycode form.
    pub fn entry_by_hostname(&self, hostname: &str) -> Option<Arc<LanDeviceEntry>> {
        let punycode = idna::domain_to_ascii(hostname).ok()?;
        let id = *self.by_hostname.get(&punycode)?;
        Some(self.entries.get(&id)?.value().clone())
    }

    // ── Test support ─────────────────────────────────────────────────────
    // Cross-crate fixtures (landscape-dns unit tests and the test_dns_server
    // bin): cfg(test) items are invisible to dependent crates, so these stay
    // compiled unconditionally. Same-crate test helpers live in tests.rs
    // (cfg(test)-only) instead. Not intended for production use.

    #[doc(hidden)]
    pub fn new_for_test() -> Arc<Self> {
        Self::with_seed(&[], None)
    }

    /// Seeds enrolled devices through the same folding path as production
    /// ([`Self::with_seed`]), so tests in other crates never build the full
    /// config type.
    #[doc(hidden)]
    pub fn new_seeded_for_test(devices: Vec<DirectorySeedDevice>) -> Arc<Self> {
        let devices: Vec<EnrolledDevice> = devices.into_iter().map(EnrolledDevice::from).collect();
        Self::with_seed(&devices, None)
    }

    #[doc(hidden)]
    pub fn apply_ipv6_event_for_test(&self, event: IPv6AssignEvent) {
        self.apply_ipv6_event(event);
    }
}

/// Minimal identity fixture for cross-crate directory tests. Each seed is
/// folded as an [`EnrolledDeviceEvent::Updated`] with a fresh id;
/// wire-observed addresses still enter via the `*_for_test` event helpers.
/// Not intended for production use.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct DirectorySeedDevice {
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
    /// Enrolled static IPv6 (PD deployments use its interface id as the
    /// address suffix).
    pub ipv6: Option<Ipv6Addr>,
}

impl From<DirectorySeedDevice> for EnrolledDevice {
    fn from(seed: DirectorySeedDevice) -> Self {
        Self {
            id: Uuid::new_v4(),
            update_at: 0.0,
            iface_name: None,
            name: "seed".to_string(),
            fake_name: None,
            remark: None,
            hostname: seed.hostname,
            mac: seed.mac,
            ipv4: seed.ipv4,
            ipv6: seed.ipv6,
            tag: vec![],
            dhcp_custom_options: vec![],
            dhcp_filter_options: vec![],
        }
    }
}
