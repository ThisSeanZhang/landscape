//! The per-device entry and its address-source tags.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::event::hub::IPv6AssignSource;
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use uuid::Uuid;

use super::ONLINE_IDLE_SECS;

/// How an IPv4 address came to be owned by a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSourceV4 {
    /// Statically configured on the enrolled device.
    Static,
    /// Granted by the DHCPv4 server.
    Lease,
    /// Observed by the periodic ARP scan (weakest evidence).
    Arp,
}

impl AddressSourceV4 {
    /// Evidence strength: the lower the rank, the stronger the claim in
    /// address arbitration (`claim_ipv4`).
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::Static => 0,
            Self::Lease => 1,
            Self::Arp => 2,
        }
    }
}

/// How an IPv6 address came to be owned by a device. `Static` is derived:
/// an assigned address whose interface identifier matches the enrolled
/// device's configured suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSourceV6 {
    Static,
    Dhcpv6,
    Slaac,
}

impl AddressSourceV6 {
    /// Evidence strength: the lower the rank, the stronger the claim in
    /// address arbitration (`claim_ipv6`).
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::Static => 0,
            Self::Dhcpv6 => 1,
            Self::Slaac => 2,
        }
    }

    pub(super) fn from_event(
        source: IPv6AssignSource,
        enrolled_suffix: Option<u64>,
        ip: Ipv6Addr,
    ) -> Self {
        if enrolled_suffix.is_some_and(|suffix| ipv6_interface_id(ip) == suffix) {
            return Self::Static;
        }
        match source {
            IPv6AssignSource::Slaac => Self::Slaac,
            IPv6AssignSource::Dhcpv6 => Self::Dhcpv6,
        }
    }
}

pub(super) fn ipv6_interface_id(ip: Ipv6Addr) -> u64 {
    let octets = ip.octets();
    u64::from_be_bytes(octets[8..16].try_into().expect("8 bytes"))
}

/// A single device as seen by the LAN. Immutable; the projection replaces
/// whole entries (copy-on-write) instead of mutating them in place.
#[derive(Debug, Clone)]
pub struct LanDeviceEntry {
    /// Internal directory key (not the enrolled device id).
    pub entry_id: Uuid,
    /// Strong anchor. `None` for IP-anchored observations from L3 sources.
    pub mac: Option<MacAddr>,
    /// Present once the device is enrolled (or an assignment event carried
    /// the id of a static binding).
    pub device_id: Option<Uuid>,
    /// User-chosen display name (enrolled devices only).
    pub display_name: Option<String>,
    /// Hostname in punycode form. Enrolled hostnames win over DHCP-learned
    /// ones (adjudicated at write time).
    pub hostname: Option<String>,
    pub hostname_from_enroll: bool,
    /// Interface identifier of the enrolled device's static IPv6 suffix,
    /// used to tag assigned addresses as `Static`.
    pub enrolled_ipv6_suffix: Option<u64>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv4_source: Option<AddressSourceV4>,
    pub ipv6_addrs: HashMap<Ipv6Addr, AddressSourceV6>,
    pub iface_name: Option<String>,
    pub last_active: f64,
}

impl LanDeviceEntry {
    pub(super) fn new(entry_id: Uuid, mac: Option<MacAddr>, now: f64) -> Self {
        Self {
            entry_id,
            mac,
            device_id: None,
            display_name: None,
            hostname: None,
            hostname_from_enroll: false,
            enrolled_ipv6_suffix: None,
            ipv4: None,
            ipv4_source: None,
            ipv6_addrs: HashMap::new(),
            iface_name: None,
            last_active: now,
        }
    }

    /// Online heuristic: an active IPv4 lease, a DHCPv6 address, or recent
    /// activity. See [`ONLINE_IDLE_SECS`] for why SLAAC alone does not count.
    pub fn is_online(&self) -> bool {
        self.ipv4.is_some()
            || self.ipv6_addrs.values().any(|s| *s == AddressSourceV6::Dhcpv6)
            || get_f64_timestamp() - self.last_active <= ONLINE_IDLE_SECS
    }

    /// AAAA answer policy: one address, preferring the most managed source
    /// (`Static > Dhcpv6 > Slaac`), ties broken by lowest address for
    /// determinism.
    pub fn preferred_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_addrs.iter().min_by_key(|(ip, source)| (source.rank(), *ip)).map(|(ip, _)| *ip)
    }
}
