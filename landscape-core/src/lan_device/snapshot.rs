//! The immutable bulk-read view derived from the live tables.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use landscape_common::net::MacAddr;
use uuid::Uuid;

use super::entry::LanDeviceEntry;

/// An immutable, mutually-consistent cut of the live tables. Bulk consumers
/// (NAT6 refresh, `/lan_devices`) hold one `Arc` of this and iterate freely.
#[derive(Debug, Clone, Default)]
pub struct DirectorySnapshot {
    pub entries: HashMap<Uuid, Arc<LanDeviceEntry>>,
    pub by_mac: HashMap<MacAddr, Arc<LanDeviceEntry>>,
    pub by_ipv4: HashMap<Ipv4Addr, Arc<LanDeviceEntry>>,
    pub by_ipv6: HashMap<Ipv6Addr, Arc<LanDeviceEntry>>,
    pub by_device_id: HashMap<Uuid, Arc<LanDeviceEntry>>,
    /// punycode hostname -> entry (enrolled priority already adjudicated).
    pub by_hostname: HashMap<String, Arc<LanDeviceEntry>>,
    pub built_at: f64,
}

impl DirectorySnapshot {
    /// device_id -> its observed IPv6 set, the shape the static NAT v6 rule
    /// resolver consumes.
    pub fn ipv6_sets_by_device_id(&self) -> HashMap<Uuid, HashSet<Ipv6Addr>> {
        let mut out = HashMap::with_capacity(self.by_device_id.len());
        for (device_id, entry) in &self.by_device_id {
            out.insert(*device_id, entry.ipv6_addrs.keys().copied().collect());
        }
        out
    }
}
