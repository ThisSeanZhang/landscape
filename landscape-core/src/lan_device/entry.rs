//! The per-device entry and its address-source tags.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::LAND_ARP_SCAN_INTERVAL;
use landscape_common::event::hub::IPv6AssignSource;
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;
use uuid::Uuid;

use super::ONLINE_WINDOW_MS;

/// Liveness trail: one bit per ARP scan interval ([`LAND_ARP_SCAN_INTERVAL`]),
/// 24 slots — 24h in release builds, 2h in debug. A set bit means the device
/// answered the scan in that bucket; buckets between observations read as
/// absent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ArpPresence {
    /// Bucket index (`ts / LAND_ARP_SCAN_INTERVAL`) of the newest bucket
    /// covered by `bits`. `0` means never seen.
    last_bucket: u64,
    /// 24-bit ring: bit `bucket % 24` is set when that bucket answered.
    bits: u32,
}

impl ArpPresence {
    const SLOTS: u64 = 24;

    pub fn mark_seen(&mut self, now_ms: f64) {
        let bucket = ms_to_bucket(now_ms);
        if bucket <= self.last_bucket {
            // Same bucket (or backdated clock): idempotently set the bit.
            self.bits |= 1 << (self.last_bucket % Self::SLOTS);
            return;
        }
        let delta = bucket - self.last_bucket;
        if delta >= Self::SLOTS {
            // The whole window aged out since the last observation.
            self.bits = 0;
        } else {
            // The `delta` oldest slots leave the window; their positions are
            // the `delta` consecutive slots ending at (and including) the new
            // bucket's slot, which the new observation then reclaims.
            let newest = bucket % Self::SLOTS;
            for k in 0..delta {
                self.bits &= !(1 << ((newest + Self::SLOTS - k) % Self::SLOTS));
            }
        }
        self.last_bucket = bucket;
        self.bits |= 1 << (bucket % Self::SLOTS);
    }

    /// The 24 buckets ending at the bucket containing `now_ms`; index 0 is
    /// the oldest. Unobserved buckets read as absent.
    pub fn series(&self, now_ms: f64) -> Vec<bool> {
        let current = ms_to_bucket(now_ms);
        (0..Self::SLOTS)
            .rev()
            .map(|k| {
                let bucket = current.saturating_sub(k);
                let in_window = bucket <= self.last_bucket
                    && self.last_bucket - bucket < Self::SLOTS
                    && self.last_bucket != 0;
                in_window && (self.bits & (1 << (bucket % Self::SLOTS))) != 0
            })
            .collect()
    }
}

fn ms_to_bucket(now_ms: f64) -> u64 {
    (now_ms as u64) / LAND_ARP_SCAN_INTERVAL
}

/// DHCPv4 lease timing attached to an entry by `Allocated` events. `ip`
/// identifies which lease the clock belongs to so an `Expired` for an old
/// address cannot wipe a newer lease's timing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DhcpLeaseTimes {
    pub ip: Ipv4Addr,
    /// Epoch milliseconds of the last request/assignment/renewal.
    pub last_request: f64,
    /// Epoch milliseconds when the lease expires (`last_request + lease_time`).
    pub expires: f64,
}

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
    /// Epoch milliseconds of the last device-side observation (ARP/ND
    /// discovery, DHCP allocation). Configuration events (enrollment
    /// pushes, expiry bookkeeping, PD flushes) never refresh it.
    /// `0.0` = enrolled but never observed.
    pub last_active: f64,
    /// ARP liveness trail (strictly ARP-sourced observations; ND does not
    /// count). Silent field: changes never emit `LanDeviceChange`.
    pub arp_presence: ArpPresence,
    /// Most recent ARP scan answer, epoch milliseconds.
    pub arp_last_seen: Option<f64>,
    /// DHCPv4 lease clock of the most recent `Allocated` event.
    /// Silent field: changes never emit `LanDeviceChange`.
    pub dhcp_lease: Option<DhcpLeaseTimes>,
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
            arp_presence: ArpPresence::default(),
            arp_last_seen: None,
            dhcp_lease: None,
        }
    }

    /// Online heuristic: recent device contact, an unexpired DHCPv4
    /// lease, or a server-tracked DHCPv6 address. A lingering
    /// ARP-observed IPv4 is inventory, not liveness. See
    /// [`super::ONLINE_WINDOW_MS`] for why SLAAC alone does not count.
    pub fn is_online(&self) -> bool {
        let now = get_f64_timestamp();
        now - self.last_active <= ONLINE_WINDOW_MS
            || self.dhcp_lease.as_ref().is_some_and(|l| l.expires > now)
            || self.ipv6_addrs.values().any(|s| *s == AddressSourceV6::Dhcpv6)
    }

    /// AAAA answer policy: one address, preferring the most managed source
    /// (`Static > Dhcpv6 > Slaac`), ties broken by lowest address for
    /// determinism.
    pub fn preferred_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6_addrs.iter().min_by_key(|(ip, source)| (source.rank(), *ip)).map(|(ip, _)| *ip)
    }
}
