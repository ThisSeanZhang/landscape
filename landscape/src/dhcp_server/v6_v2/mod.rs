use std::{collections::HashMap, net::Ipv6Addr, time::Instant};

use landscape_common::{
    dhcp::v6_server::{
        config::{DHCPv6IANAConfig, DHCPv6IAPDConfig},
        status::{DHCPv6AddressItem, DHCPv6OfferInfo, DHCPv6PrefixItem},
    },
    enrolled_device::EnrolledDevice,
    ipv6::lan::{LanPrefixGroupConfig, PrefixParentSource},
    ipv6_pd::IAPrefixMap,
    lan_services::ipv6_ra::{IPv6NAInfo, IPv6NAInfoItem},
    net::MacAddr,
    utils::time::get_f64_timestamp,
};

pub mod connection;
pub mod dhcpv6;
pub mod icmpv6;
pub mod pd;
pub mod server;

use self::pd::{PdRange, PdSlotKey};

// ── Internal lease types ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NaLease {
    pub suffix: u64,
    pub duid_hex: String,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub preferred_time: u32,
    pub is_static: bool,
    pub prev_suffix: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PdLease {
    pub group_id: String,
    pub sub_index: u32,
    pub duid_hex: String,
    pub relative_offer_time: u64,
    pub valid_time: u32,
    pub preferred_time: u32,
    pub client_addr: Ipv6Addr,
    pub active_routes: Vec<(Ipv6Addr, u8)>,
}

// ── Suffix ownership ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuffixOwner {
    StaticMac(MacAddr),
    DynamicDuid(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NaAddressCheck {
    Owned,
    NotOnLink,
    Unallocated,
    OwnedByOtherMac(MacAddr),
    OwnedByOtherDuid(Vec<u8>),
}

// ── Lease change tracking ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NaLeaseChange {
    pub lease: NaLease,
    pub previous_suffix: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct LeaseChangeSet {
    pub allocated: Vec<NaLeaseChange>,
    pub expired: Vec<NaLeaseChange>,
    pub released: Vec<NaLease>,
}

impl LeaseChangeSet {
    pub fn push_allocated(&mut self, lease: NaLease, previous_suffix: Option<u64>) {
        self.allocated.push(NaLeaseChange { lease, previous_suffix });
    }

    pub fn push_expired(&mut self, lease: NaLease, previous_suffix: Option<u64>) {
        self.expired.push(NaLeaseChange { lease, previous_suffix });
    }
}

#[derive(Debug, Clone)]
pub enum MacSuffixBindResult {
    Bound(LeaseChangeSet),
    AlreadyBound,
    StaticConflict { owner: MacAddr },
    InvariantViolation { reason: String },
}

#[derive(Debug, Clone)]
pub enum DeviceBindingResult {
    Bound(LeaseChangeSet),
    Removed(LeaseChangeSet),
    AlreadyBound,
    StaticConflict { owner: MacAddr },
    InvariantViolation { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdRouteCleanup {
    pub sub_index: u32,
    pub routes: Vec<(Ipv6Addr, u8)>,
}

// ── View / event types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExpiredNa {
    pub ip: Ipv6Addr,
    pub suffix: u64,
    pub mac: Option<MacAddr>,
    pub duid_hex: String,
}

#[derive(Debug, Clone)]
pub struct ExpiredPd {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub sub_index: u32,
    pub duid_hex: String,
    pub active_routes: Vec<(Ipv6Addr, u8)>,
}

#[derive(Debug, Clone)]
pub struct SlaacEntry {
    pub mac: MacAddr,
    pub relative_active_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSource {
    Slaac,
    Dhcpv6Na,
}

#[derive(Debug, Clone)]
pub struct AssignedAddr {
    pub ip: Ipv6Addr,
    pub mac: Option<MacAddr>,
    pub duid: Option<String>,
    pub hostname: Option<String>,
    pub source: AddrSource,
    pub is_static: bool,
    pub relative_active_time: u64,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

#[derive(Debug, Clone)]
pub struct DelegatedPrefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub duid: Option<String>,
    pub relative_active_time: u64,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

// ── Prefix resolution result types ─────────────────────────────────────────

pub struct RaEntry {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

pub struct NaEntry {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
}

pub struct PrefixState {
    pub ra_entries: Vec<RaEntry>,
    pub na_entries: Vec<NaEntry>,
    pub pd_ranges: Vec<PdRange>,
}

impl PrefixState {
    pub fn new() -> Self {
        PrefixState {
            ra_entries: Vec::new(),
            na_entries: Vec::new(),
            pd_ranges: Vec::new(),
        }
    }

    pub fn refresh(&mut self, groups: &[LanPrefixGroupConfig], prefix_map: &IAPrefixMap) {
        self.ra_entries.clear();
        self.na_entries.clear();
        self.pd_ranges.clear();

        for group in groups {
            let (parent_ip, parent_len, pd_lifetimes) = match &group.parent {
                PrefixParentSource::Static { base_prefix, parent_prefix_len } => (
                    pd::normalize_prefix(*base_prefix, *parent_prefix_len),
                    *parent_prefix_len,
                    (0u32, 0u32),
                ),
                PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len: _ } => {
                    match prefix_map.load(depend_iface) {
                        Some(prefix) => (
                            pd::normalize_prefix(prefix.prefix_ip, prefix.prefix_len),
                            prefix.prefix_len,
                            (prefix.preferred_lifetime, prefix.valid_lifetime),
                        ),
                        None => continue,
                    }
                }
            };

            if let Some(ra) = &group.ra {
                let (pref_lt, valid_lt) = match &group.parent {
                    PrefixParentSource::Static { .. } => (ra.preferred_lifetime, ra.valid_lifetime),
                    PrefixParentSource::Pd { .. } => pd_lifetimes,
                };
                self.ra_entries.push(RaEntry {
                    prefix: parent_ip,
                    prefix_len: parent_len,
                    preferred_lifetime: pref_lt,
                    valid_lifetime: valid_lt,
                });
            }

            if group.na.is_some() {
                self.na_entries.push(NaEntry { prefix: parent_ip, prefix_len: parent_len });
            }

            if let Some(pd) = &group.pd {
                let (pref_lt, valid_lt) = match &group.parent {
                    PrefixParentSource::Static { .. } => {
                        if let Some(ra) = &group.ra {
                            (ra.preferred_lifetime, ra.valid_lifetime)
                        } else {
                            (0u32, 0u32)
                        }
                    }
                    PrefixParentSource::Pd { .. } => pd_lifetimes,
                };
                self.pd_ranges.push(PdRange {
                    group_id: group.group_id.clone(),
                    parent: parent_ip,
                    parent_len,
                    pool_len: pd.pool_len,
                    start_idx: pd.start_index,
                    end_idx: pd.end_index,
                    preferred_lifetime: pref_lt,
                    valid_lifetime: valid_lt,
                });
            }
        }
    }
}

// ── Reply params (pre-computed once per server start) ──────────────────────

#[derive(Debug, Clone)]
pub struct Ipv6LanReplyParams {
    pub na_preferred_lifetime: u32,
    pub na_valid_lifetime: u32,
    pub pd_preferred_lifetime: u32,
    pub pd_valid_lifetime: u32,
    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

// ── Ipv6ServerStatus ───────────────────────────────────────────────────────

pub struct Ipv6ServerStatus {
    // ── Config ──
    na_config: Option<DHCPv6IANAConfig>,
    pd_config: Option<DHCPv6IAPDConfig>,

    // ── Prefix state ──
    prefix_state: PrefixState,

    // ── NA allocator state ──
    na_pool_start: u64,
    na_range_capacity: u64,
    na_leases_by_duid: HashMap<Vec<u8>, NaLease>,
    na_owners_by_suffix: HashMap<u64, SuffixOwner>,
    na_static_by_mac: HashMap<MacAddr, u64>,

    // ── PD allocator state ──
    pd_leases_by_duid: HashMap<Vec<u8>, PdLease>,
    /// (group_id, sub_index) → DUID — flattened ownership map
    pd_owners_by_slot: HashMap<(String, u32), Vec<u8>>,

    // ── SLAAC tracking ──
    slaac_entries: HashMap<Ipv6Addr, SlaacEntry>,

    // ── Timing ──
    boot_time: Instant,
    boot_time_f64: f64,
}

impl Ipv6ServerStatus {
    // ── construction ───────────────────────────────────────────────────────

    pub fn new(
        na_config: Option<DHCPv6IANAConfig>,
        pd_config: Option<DHCPv6IAPDConfig>,
        devices: Vec<EnrolledDevice>,
    ) -> Self {
        let na_pool_start = na_config.as_ref().map(|c| c.pool_start).unwrap_or(0);
        let na_pool_end = na_config
            .as_ref()
            .and_then(|c| c.pool_end)
            .unwrap_or(na_pool_start.saturating_add(0xFFFF));
        let na_range_capacity = na_pool_end.saturating_sub(na_pool_start);

        let mut status = Ipv6ServerStatus {
            na_config,
            pd_config,
            prefix_state: PrefixState::new(),
            na_pool_start,
            na_range_capacity,
            na_leases_by_duid: HashMap::new(),
            na_owners_by_suffix: HashMap::new(),
            na_static_by_mac: HashMap::new(),
            pd_leases_by_duid: HashMap::new(),
            pd_owners_by_slot: HashMap::new(),
            slaac_entries: HashMap::new(),
            boot_time: Instant::now(),
            boot_time_f64: get_f64_timestamp(),
        };

        for device in devices {
            if let Some(ipv6) = device.ipv6 {
                let suffix = ipv6_suffix(ipv6);
                status.na_static_by_mac.insert(device.mac, suffix);
                status.na_owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(device.mac));
            }
        }

        status
    }

    // ── prefix management ──────────────────────────────────────────────────

    pub fn update_prefix(&mut self, groups: &[LanPrefixGroupConfig], prefix_map: &IAPrefixMap) {
        self.prefix_state.refresh(groups, prefix_map);
    }

    pub fn ra_entries(&self) -> &[RaEntry] {
        &self.prefix_state.ra_entries
    }

    pub fn na_entries(&self) -> &[NaEntry] {
        &self.prefix_state.na_entries
    }

    pub fn pd_ranges(&self) -> &[PdRange] {
        &self.prefix_state.pd_ranges
    }

    pub fn resolve_pd_prefix(&self, key: &PdSlotKey) -> Option<(Ipv6Addr, u8)> {
        pd::resolve_pd_prefix(&self.prefix_state.pd_ranges, key)
    }

    pub(crate) fn pd_lease_sub_index(&self, duid: &[u8]) -> Option<u32> {
        self.pd_leases_by_duid.get(duid).map(|l| l.sub_index)
    }

    // ── helpers ────────────────────────────────────────────────────────────

    /// Prefixes eligible for NA address allocation (filtered by max_prefix_len).
    fn qualifying_na_prefixes(&self) -> Vec<(Ipv6Addr, u8)> {
        match &self.na_config {
            Some(cfg) => self
                .prefix_state
                .na_entries
                .iter()
                .filter(|e| e.prefix_len <= cfg.max_prefix_len)
                .map(|e| (e.prefix, e.prefix_len))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Check whether `ip` falls within any qualifying NA prefix.
    fn is_na_on_link(&self, ip: Ipv6Addr) -> bool {
        self.qualifying_na_prefixes().iter().any(|(prefix, prefix_len)| {
            let mask = if *prefix_len >= 128 { !0u128 } else { !0u128 << (128 - prefix_len) };
            (u128::from(ip) & mask) == (u128::from(*prefix) & mask)
        })
    }

    // ── NA: DHCPv6 IA_NA address allocation ────────────────────────────────

    /// Allocate or return existing NA addresses for a client.
    /// Returns all addresses (one per qualifying prefix) for the assigned suffix.
    pub fn offer_na(
        &mut self,
        duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
    ) -> Option<Vec<Ipv6Addr>> {
        let now = self.boot_time.elapsed().as_secs();

        // 1. static binding: if MAC has a pre-configured suffix, assign it
        if let Some(mac) = mac {
            if let Some(&suffix) = self.na_static_by_mac.get(&mac) {
                self.insert_static_na_lease(duid, mac, suffix, hostname, now);
                return Some(self.suffix_to_addrs(suffix));
            }
        }

        // 2. existing DUID lease: return current addresses
        if let Some(lease) = self.na_leases_by_duid.get(duid) {
            return Some(self.suffix_to_addrs(lease.suffix));
        }

        // 3. allocate new dynamic suffix
        let na_config = self.na_config.as_ref()?.clone();
        let suffix =
            self.allocate_dynamic_na_suffix(duid, mac, hostname, now, None, None, &na_config)?;
        Some(self.suffix_to_addrs(suffix))
    }

    pub fn confirm_na(&mut self, duid: &[u8]) -> bool {
        let na_config = match &self.na_config {
            Some(c) => c,
            None => return false,
        };
        let now = self.boot_time.elapsed().as_secs();
        if let Some(lease) = self.na_leases_by_duid.get_mut(duid) {
            if !lease.is_static {
                lease.valid_time = na_config.valid_lifetime;
            }
            lease.preferred_time = na_config.preferred_lifetime;
            lease.relative_offer_time = now;
            true
        } else {
            false
        }
    }

    pub fn release_na(&mut self, duid: &[u8]) -> Option<ExpiredNa> {
        self.remove_na_lease(duid).map(|(_lease, ip)| ip)
    }

    pub fn clean_expired_na(&mut self) -> Vec<ExpiredNa> {
        let now = self.boot_time.elapsed().as_secs();
        let expired_duids: Vec<Vec<u8>> = self
            .na_leases_by_duid
            .iter()
            .filter(|(_, lease)| {
                !lease.is_static && now > lease.relative_offer_time + lease.valid_time as u64
            })
            .map(|(duid, _)| duid.clone())
            .collect();

        let mut result = Vec::new();
        for duid in expired_duids {
            if let Some(expired) = self.remove_na_lease(&duid) {
                result.push(expired.1);
            }
        }
        result
    }

    pub fn get_na_addresses(&self, duid: &[u8]) -> Vec<Ipv6Addr> {
        self.na_leases_by_duid
            .get(duid)
            .map(|lease| self.suffix_to_addrs(lease.suffix))
            .unwrap_or_default()
    }

    pub fn has_na_offer(&self, duid: &[u8]) -> bool {
        self.na_leases_by_duid.contains_key(duid)
    }

    pub fn consume_prev_suffix(&mut self, duid: &[u8]) {
        if let Some(lease) = self.na_leases_by_duid.get_mut(duid) {
            lease.prev_suffix = None;
        }
    }

    pub fn check_address_owner(
        &self,
        ip: Ipv6Addr,
        duid: &[u8],
        mac: Option<MacAddr>,
    ) -> NaAddressCheck {
        if !self.is_na_on_link(ip) {
            return NaAddressCheck::NotOnLink;
        }
        let suffix = ipv6_suffix(ip);
        match self.na_owners_by_suffix.get(&suffix) {
            Some(SuffixOwner::StaticMac(owner)) => {
                if Some(*owner) == mac {
                    NaAddressCheck::Owned
                } else {
                    NaAddressCheck::OwnedByOtherMac(*owner)
                }
            }
            Some(SuffixOwner::DynamicDuid(owner)) => {
                if owner == duid {
                    NaAddressCheck::Owned
                } else {
                    NaAddressCheck::OwnedByOtherDuid(owner.clone())
                }
            }
            None => NaAddressCheck::Unallocated,
        }
    }

    // ── NA binding (enrolled device) ───────────────────────────────────────

    /// Add/update or remove a static MAC→suffix binding from enrolled devices.
    /// `Some(ipv6)` = bind, `None` = unbind.
    pub fn update_device_binding(
        &mut self,
        mac: MacAddr,
        ipv6: Option<Ipv6Addr>,
    ) -> DeviceBindingResult {
        match ipv6 {
            Some(ip) => {
                let suffix = ipv6_suffix(ip);
                match self.bind_mac_suffix(mac, suffix) {
                    MacSuffixBindResult::Bound(changes) => DeviceBindingResult::Bound(changes),
                    MacSuffixBindResult::AlreadyBound => DeviceBindingResult::AlreadyBound,
                    MacSuffixBindResult::StaticConflict { owner } => {
                        DeviceBindingResult::StaticConflict { owner }
                    }
                    MacSuffixBindResult::InvariantViolation { reason } => {
                        DeviceBindingResult::InvariantViolation { reason }
                    }
                }
            }
            None => DeviceBindingResult::Removed(self.remove_mac_binding(&mac)),
        }
    }

    pub fn bind_mac_suffix(&mut self, mac: MacAddr, suffix: u64) -> MacSuffixBindResult {
        let now = self.boot_time.elapsed().as_secs();

        // Already bound — no-op
        if self.na_static_by_mac.get(&mac) == Some(&suffix)
            && self.na_owners_by_suffix.get(&suffix) == Some(&SuffixOwner::StaticMac(mac))
        {
            return MacSuffixBindResult::AlreadyBound;
        }

        // Conflict: suffix is statically owned by another MAC
        if let Some(SuffixOwner::StaticMac(owner)) = self.na_owners_by_suffix.get(&suffix) {
            if *owner != mac {
                return MacSuffixBindResult::StaticConflict { owner: *owner };
            }
        }

        let old_static_suffix = self.na_static_by_mac.get(&mac).copied();
        if let Some(old) = old_static_suffix {
            if old != suffix {
                match self.na_owners_by_suffix.get(&old) {
                    Some(SuffixOwner::StaticMac(owner)) if *owner == mac => {}
                    Some(_) => {
                        return MacSuffixBindResult::InvariantViolation {
                            reason: format!(
                                "static suffix {old} for {mac} owned by another source"
                            ),
                        };
                    }
                    None => {}
                }
            }
        }

        let mut changes = LeaseChangeSet::default();
        let mac_duid = self.lease_duid_for_mac(mac);

        self.na_static_by_mac.insert(mac, suffix);
        if let Some(old) = old_static_suffix {
            if old != suffix
                && self.na_owners_by_suffix.get(&old) == Some(&SuffixOwner::StaticMac(mac))
            {
                self.na_owners_by_suffix.remove(&old);
            }
        }

        if let Some(ref duid) = mac_duid {
            if let Some(lease) = self.na_leases_by_duid.get(duid) {
                self.remove_dynamic_owner_if_matches(lease.suffix, duid);
            }
        }

        // Evict dynamic occupant
        match self.na_owners_by_suffix.remove(&suffix) {
            Some(SuffixOwner::DynamicDuid(evicted_duid)) => {
                if mac_duid.as_ref() != Some(&evicted_duid) {
                    if let Some(mut evicted) = self.na_leases_by_duid.remove(&evicted_duid) {
                        changes.push_expired(evicted.clone(), Some(suffix));

                        if let Some(old) = old_static_suffix {
                            if old != suffix
                                && (old >= self.na_pool_start)
                                && (old < self.na_pool_start + self.na_range_capacity)
                                && !self.na_owners_by_suffix.contains_key(&old)
                            {
                                evicted.prev_suffix = Some(suffix);
                                evicted.suffix = old;
                                evicted.is_static = false;
                                evicted.relative_offer_time = now;
                                evicted.valid_time = OFFER_VALID_TIME;
                                evicted.preferred_time = self
                                    .na_config
                                    .as_ref()
                                    .map(|c| c.preferred_lifetime.min(OFFER_VALID_TIME))
                                    .unwrap_or(OFFER_VALID_TIME);
                                self.na_owners_by_suffix
                                    .insert(old, SuffixOwner::DynamicDuid(evicted_duid.clone()));
                                self.na_leases_by_duid.insert(evicted_duid, evicted.clone());
                                changes.push_allocated(evicted, Some(suffix));
                            }
                        } else if let Some(na_config) = self.na_config.clone() {
                            if self
                                .allocate_dynamic_na_suffix(
                                    &evicted_duid,
                                    evicted.mac,
                                    evicted.hostname.clone(),
                                    now,
                                    Some(suffix),
                                    Some(suffix),
                                    &na_config,
                                )
                                .is_some()
                            {
                                let reassigned_lease = self
                                    .na_leases_by_duid
                                    .get(&evicted_duid)
                                    .cloned()
                                    .expect("just inserted");
                                changes.push_allocated(reassigned_lease, Some(suffix));
                            } else {
                                changes.released.push(evicted);
                            }
                        } else {
                            changes.released.push(evicted);
                        }
                    }
                }
            }
            _ => {}
        }

        self.na_owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(mac));
        if let Some(duid) = mac_duid {
            if let Some(lease) = self.na_leases_by_duid.get_mut(&duid) {
                let previous = lease.suffix;
                lease.suffix = suffix;
                lease.is_static = true;
                lease.prev_suffix = (previous != suffix).then_some(previous);
                lease.relative_offer_time = now;
                lease.valid_time = self.na_config.as_ref().map(|c| c.valid_lifetime).unwrap_or(0);
                lease.preferred_time =
                    self.na_config.as_ref().map(|c| c.preferred_lifetime).unwrap_or(0);
                changes.push_allocated(lease.clone(), (previous != suffix).then_some(previous));
            }
        }

        MacSuffixBindResult::Bound(changes)
    }

    pub fn remove_mac_binding(&mut self, mac: &MacAddr) -> LeaseChangeSet {
        let now = self.boot_time.elapsed().as_secs();
        let Some(old_suffix) = self.na_static_by_mac.remove(mac) else {
            return LeaseChangeSet::default();
        };
        if self.na_owners_by_suffix.get(&old_suffix) == Some(&SuffixOwner::StaticMac(*mac)) {
            self.na_owners_by_suffix.remove(&old_suffix);
        }

        let Some(duid) = self.static_lease_duid_for_mac(*mac) else {
            return LeaseChangeSet::default();
        };
        let Some(mut lease) = self.na_leases_by_duid.remove(&duid) else {
            return LeaseChangeSet::default();
        };

        let mut changes = LeaseChangeSet::default();
        changes.push_expired(lease.clone(), Some(old_suffix));

        let in_dynamic_pool = old_suffix >= self.na_pool_start
            && old_suffix < self.na_pool_start + self.na_range_capacity;
        if in_dynamic_pool && !self.na_owners_by_suffix.contains_key(&old_suffix) {
            lease.is_static = false;
            lease.prev_suffix = Some(old_suffix);
            lease.relative_offer_time = now;
            lease.valid_time = self.na_config.as_ref().map(|c| c.valid_lifetime).unwrap_or(0);
            lease.preferred_time =
                self.na_config.as_ref().map(|c| c.preferred_lifetime).unwrap_or(0);
            self.na_owners_by_suffix.insert(old_suffix, SuffixOwner::DynamicDuid(duid.clone()));
            self.na_leases_by_duid.insert(duid, lease.clone());
            changes.push_allocated(lease, Some(old_suffix));
        } else if let Some(na_config) = self.na_config.clone() {
            if self
                .allocate_dynamic_na_suffix(
                    &duid,
                    lease.mac,
                    lease.hostname.clone(),
                    now,
                    Some(old_suffix),
                    None,
                    &na_config,
                )
                .is_some()
            {
                let reassigned = self.na_leases_by_duid.get(&duid).cloned().expect("just inserted");
                changes.push_allocated(reassigned, Some(old_suffix));
            } else {
                changes.released.push(lease);
            }
        } else {
            changes.released.push(lease);
        }
        changes
    }

    // ── PD: DHCPv6 prefix delegation ───────────────────────────────────────

    pub fn offer_pd(&mut self, duid: &[u8]) -> Option<(Ipv6Addr, u8)> {
        let pd_config = self.pd_config.as_ref()?;
        let now = self.boot_time.elapsed().as_secs();

        // Re-use existing lease if the slot is still valid
        if let Some(lease) = self.pd_leases_by_duid.get(duid) {
            let key = (lease.group_id.clone(), lease.sub_index);
            if self.pd_owners_by_slot.get(&key) == Some(&duid.to_vec()) {
                if let Some((prefix, prefix_len)) = self.resolve_pd_key(&key) {
                    return Some((prefix, prefix_len));
                }
            }
            // Slot became invalid — remove stale lease
            self.pd_leases_by_duid.remove(duid);
            self.pd_owners_by_slot.remove(&key);
        }

        // Find a free slot across all pd_ranges
        let (group_id, sub_index) = self.find_free_pd_slot()?;
        let key = (group_id.clone(), sub_index);

        let (prefix, prefix_len) = self.resolve_pd_key(&key)?;

        let lease = PdLease {
            group_id,
            sub_index,
            duid_hex: duid_to_hex(duid),
            relative_offer_time: now,
            valid_time: OFFER_VALID_TIME,
            preferred_time: pd_config.preferred_lifetime.min(OFFER_VALID_TIME),
            client_addr: Ipv6Addr::UNSPECIFIED,
            active_routes: Vec::new(),
        };
        self.pd_leases_by_duid.insert(duid.to_vec(), lease);
        self.pd_owners_by_slot.insert(key, duid.to_vec());

        Some((prefix, prefix_len))
    }

    pub fn confirm_pd(&mut self, duid: &[u8]) -> bool {
        let pd_config = match &self.pd_config {
            Some(c) => c,
            None => return false,
        };
        let now = self.boot_time.elapsed().as_secs();
        if let Some(lease) = self.pd_leases_by_duid.get_mut(duid) {
            lease.valid_time = pd_config.valid_lifetime;
            lease.preferred_time = pd_config.preferred_lifetime;
            lease.relative_offer_time = now;
            true
        } else {
            false
        }
    }

    pub fn release_pd(&mut self, duid: &[u8]) -> Option<ExpiredPd> {
        let lease = self.pd_leases_by_duid.remove(duid)?;
        let key = (lease.group_id.clone(), lease.sub_index);
        self.pd_owners_by_slot.remove(&key);

        let (prefix, prefix_len) = self.resolve_pd_key(&key)?;
        Some(ExpiredPd {
            prefix,
            prefix_len,
            sub_index: lease.sub_index,
            duid_hex: lease.duid_hex,
            active_routes: lease.active_routes,
        })
    }

    pub fn clean_expired_pd(&mut self) -> Vec<ExpiredPd> {
        let now = self.boot_time.elapsed().as_secs();
        let expired_duids: Vec<Vec<u8>> = self
            .pd_leases_by_duid
            .iter()
            .filter(|(_, lease)| now > lease.relative_offer_time + lease.valid_time as u64)
            .map(|(duid, _)| duid.clone())
            .collect();

        let mut result = Vec::new();
        for duid in expired_duids {
            if let Some(expired) = self.release_pd(&duid) {
                result.push(expired);
            }
        }
        result
    }

    pub fn get_pd_prefix(&self, duid: &[u8]) -> Option<(Ipv6Addr, u8)> {
        let lease = self.pd_leases_by_duid.get(duid)?;
        let key = (lease.group_id.clone(), lease.sub_index);
        self.resolve_pd_key(&key)
    }

    pub fn has_pd_offer(&self, duid: &[u8]) -> bool {
        self.pd_leases_by_duid.contains_key(duid)
    }

    pub fn update_pd_routes(
        &mut self,
        duid: &[u8],
        client_addr: Ipv6Addr,
        routes: Vec<(Ipv6Addr, u8)>,
    ) -> Option<Vec<(Ipv6Addr, u8)>> {
        let lease = self.pd_leases_by_duid.get_mut(duid)?;
        let old = std::mem::replace(&mut lease.active_routes, routes);
        lease.client_addr = client_addr;
        Some(old)
    }

    pub fn reconcile_pd_routes(&mut self) -> Vec<PdRouteCleanup> {
        // Resolve expected prefixes first (immutable pass).
        let resolved: Vec<(Vec<u8>, Option<(Ipv6Addr, u8)>)> = self
            .pd_leases_by_duid
            .iter()
            .filter(|(_, lease)| !lease.active_routes.is_empty())
            .map(|(duid, lease)| {
                let key = (lease.group_id.clone(), lease.sub_index);
                (duid.clone(), self.resolve_pd_key(&key))
            })
            .collect();

        let mut cleanups = Vec::new();
        for (duid, expected) in resolved {
            let Some(lease) = self.pd_leases_by_duid.get_mut(&duid) else {
                continue;
            };
            let route_is_current = match expected {
                Some(expected) => {
                    lease.active_routes.len() == 1 && lease.active_routes[0] == expected
                }
                None => false,
            };
            if !route_is_current {
                cleanups.push(PdRouteCleanup {
                    sub_index: lease.sub_index,
                    routes: std::mem::take(&mut lease.active_routes),
                });
            }
        }
        cleanups
    }

    // ── SLAAC address tracking ─────────────────────────────────────────────

    pub fn record_slaac_addr(&mut self, mac: MacAddr, ip: Ipv6Addr) {
        let now = self.boot_time.elapsed().as_secs();
        self.slaac_entries.insert(ip, SlaacEntry { mac, relative_active_time: now });
    }

    pub fn clean_expired_slaac(&mut self, current_time: u64, threshold: u64) -> Vec<SlaacEntry> {
        let mut expired = Vec::new();
        self.slaac_entries.retain(|_ip, entry| {
            if current_time.saturating_sub(entry.relative_active_time) >= threshold {
                expired.push(entry.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    // ── queries & views ────────────────────────────────────────────────────

    /// Unified view of all assigned addresses (SLAAC + DHCPv6 NA).
    pub fn all_addresses(&self) -> Vec<AssignedAddr> {
        let mut result = Vec::new();
        let na_prefixes = self.qualifying_na_prefixes();

        for lease in self.na_leases_by_duid.values() {
            for (prefix, prefix_len) in &na_prefixes {
                result.push(AssignedAddr {
                    ip: combine_prefix_suffix(*prefix, *prefix_len, lease.suffix),
                    mac: lease.mac,
                    duid: Some(lease.duid_hex.clone()),
                    hostname: lease.hostname.clone(),
                    source: AddrSource::Dhcpv6Na,
                    is_static: lease.is_static,
                    relative_active_time: lease.relative_offer_time,
                    preferred_lifetime: lease.preferred_time,
                    valid_lifetime: lease.valid_time,
                });
            }
        }

        for (ip, entry) in &self.slaac_entries {
            result.push(AssignedAddr {
                ip: *ip,
                mac: Some(entry.mac),
                duid: None,
                hostname: None,
                source: AddrSource::Slaac,
                is_static: false,
                relative_active_time: entry.relative_active_time,
                preferred_lifetime: 0,
                valid_lifetime: 0,
            });
        }

        result
    }

    /// All delegated prefixes.
    pub fn all_delegated_prefixes(&self) -> Vec<DelegatedPrefix> {
        self.pd_leases_by_duid
            .values()
            .filter_map(|lease| {
                let key = (lease.group_id.clone(), lease.sub_index);
                self.resolve_pd_key(&key).map(|(prefix, prefix_len)| DelegatedPrefix {
                    prefix,
                    prefix_len,
                    duid: Some(lease.duid_hex.clone()),
                    relative_active_time: lease.relative_offer_time,
                    preferred_lifetime: lease.preferred_time,
                    valid_lifetime: lease.valid_time,
                })
            })
            .collect()
    }

    /// IP → client info reverse lookup.
    pub fn lookup_by_ip(&self, ip: Ipv6Addr) -> Option<AssignedAddr> {
        // Check SLAAC first (fast path for exact IP match)
        if let Some(entry) = self.slaac_entries.get(&ip) {
            return Some(AssignedAddr {
                ip,
                mac: Some(entry.mac),
                duid: None,
                hostname: None,
                source: AddrSource::Slaac,
                is_static: false,
                relative_active_time: entry.relative_active_time,
                preferred_lifetime: 0,
                valid_lifetime: 0,
            });
        }

        // Check DHCPv6 NA: resolve IP → suffix → lease
        let suffix = ipv6_suffix(ip);
        if let Some(owner) = self.na_owners_by_suffix.get(&suffix) {
            let (duid_vec, mac_opt) = match owner {
                SuffixOwner::StaticMac(mac) => {
                    let duid = self.static_lease_duid_for_mac(*mac);
                    (duid, Some(*mac))
                }
                SuffixOwner::DynamicDuid(duid) => (Some(duid.clone()), None),
            };
            if let Some(duid) = duid_vec {
                if let Some(lease) = self.na_leases_by_duid.get(&duid) {
                    return Some(AssignedAddr {
                        ip,
                        mac: lease.mac.or(mac_opt),
                        duid: Some(lease.duid_hex.clone()),
                        hostname: lease.hostname.clone(),
                        source: AddrSource::Dhcpv6Na,
                        is_static: lease.is_static,
                        relative_active_time: lease.relative_offer_time,
                        preferred_lifetime: lease.preferred_time,
                        valid_lifetime: lease.valid_time,
                    });
                }
            }
            // Static-only binding (no DUID lease yet)
            if let SuffixOwner::StaticMac(mac) = owner {
                return Some(AssignedAddr {
                    ip,
                    mac: Some(*mac),
                    duid: None,
                    hostname: None,
                    source: AddrSource::Dhcpv6Na,
                    is_static: true,
                    relative_active_time: 0,
                    preferred_lifetime: 0,
                    valid_lifetime: 0,
                });
            }
        }

        None
    }

    /// MAC → IP forward lookup (static > dynamic > SLAAC).
    pub fn lookup_ip_by_mac(&self, mac: &MacAddr) -> Option<Ipv6Addr> {
        // Static binding
        if let Some(&suffix) = self.na_static_by_mac.get(mac) {
            return self
                .qualifying_na_prefixes()
                .first()
                .map(|(prefix, prefix_len)| combine_prefix_suffix(*prefix, *prefix_len, suffix));
        }
        // Dynamic lease
        for lease in self.na_leases_by_duid.values() {
            if lease.mac == Some(*mac) {
                return self.qualifying_na_prefixes().first().map(|(prefix, prefix_len)| {
                    combine_prefix_suffix(*prefix, *prefix_len, lease.suffix)
                });
            }
        }
        // SLAAC
        for (ip, entry) in &self.slaac_entries {
            if entry.mac == *mac {
                return Some(*ip);
            }
        }
        None
    }

    // ── backward-compatible views ──────────────────────────────────────────

    pub fn to_ipv6_na_info(&self) -> IPv6NAInfo {
        IPv6NAInfo {
            boot_time: self.boot_time_f64,
            offered_ips: self
                .slaac_entries
                .iter()
                .map(|(ip, entry)| {
                    (
                        *ip,
                        IPv6NAInfoItem {
                            mac: entry.mac,
                            ip: *ip,
                            relative_active_time: entry.relative_active_time,
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn to_dhcpv6_offer_info(&self) -> DHCPv6OfferInfo {
        let relative_boot_time = self.boot_time.elapsed().as_secs();
        let na_prefixes = self.qualifying_na_prefixes();

        let offered_addresses = self
            .na_leases_by_duid
            .values()
            .flat_map(|lease| {
                na_prefixes.iter().map(|(prefix, prefix_len)| DHCPv6AddressItem {
                    duid: Some(lease.duid_hex.clone()),
                    mac: lease.mac,
                    ip: combine_prefix_suffix(*prefix, *prefix_len, lease.suffix),
                    hostname: lease.hostname.clone(),
                    relative_active_time: lease.relative_offer_time,
                    preferred_lifetime: lease.preferred_time,
                    valid_lifetime: lease.valid_time,
                    is_static: lease.is_static,
                    prev_suffix: lease.prev_suffix,
                })
            })
            .collect();

        let delegated_prefixes = self
            .pd_leases_by_duid
            .values()
            .filter_map(|lease| {
                let key = (lease.group_id.clone(), lease.sub_index);
                self.resolve_pd_key(&key).map(|(prefix, prefix_len)| DHCPv6PrefixItem {
                    duid: Some(lease.duid_hex.clone()),
                    prefix,
                    prefix_len,
                    relative_active_time: lease.relative_offer_time,
                    preferred_lifetime: lease.preferred_time,
                    valid_lifetime: lease.valid_time,
                })
            })
            .collect();

        DHCPv6OfferInfo {
            boot_time: self.boot_time_f64,
            relative_boot_time,
            offered_addresses,
            delegated_prefixes,
        }
    }

    // ── private helpers ────────────────────────────────────────────────────

    /// Convert suffix → list of full addresses (one per qualifying prefix).
    pub(crate) fn suffix_to_addrs(&self, suffix: u64) -> Vec<Ipv6Addr> {
        self.qualifying_na_prefixes()
            .iter()
            .map(|(prefix, prefix_len)| combine_prefix_suffix(*prefix, *prefix_len, suffix))
            .collect()
    }

    fn insert_static_na_lease(
        &mut self,
        duid: &[u8],
        mac: MacAddr,
        suffix: u64,
        hostname: Option<String>,
        now: u64,
    ) {
        let na_config = self.na_config.clone();
        let previous_suffix = self.na_leases_by_duid.get(duid).map(|l| l.suffix);

        if let Some(old) = previous_suffix {
            self.remove_dynamic_owner_if_matches(old, duid);
        }
        if let Some(old_duid) = self.static_lease_duid_for_mac(mac) {
            if old_duid != duid {
                self.na_leases_by_duid.remove(&old_duid);
            }
        }
        self.na_owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(mac));
        let lease = NaLease {
            suffix,
            hostname,
            mac: Some(mac),
            duid_hex: duid_to_hex(duid),
            relative_offer_time: now,
            valid_time: na_config.as_ref().map(|c| c.valid_lifetime).unwrap_or(0),
            preferred_time: na_config.as_ref().map(|c| c.preferred_lifetime).unwrap_or(0),
            is_static: true,
            prev_suffix: previous_suffix.filter(|prev| *prev != suffix),
        };
        self.na_leases_by_duid.insert(duid.to_vec(), lease);
    }

    fn remove_na_lease(&mut self, duid: &[u8]) -> Option<(NaLease, ExpiredNa)> {
        let lease = self.na_leases_by_duid.remove(duid)?;
        if !lease.is_static {
            self.remove_dynamic_owner_if_matches(lease.suffix, duid);
        }
        let ips = self.suffix_to_addrs(lease.suffix);
        let first_ip = *ips.first()?;
        Some((
            lease.clone(),
            ExpiredNa {
                ip: first_ip,
                suffix: lease.suffix,
                mac: lease.mac,
                duid_hex: lease.duid_hex,
            },
        ))
    }

    fn allocate_dynamic_na_suffix(
        &mut self,
        duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        now: u64,
        prev_suffix: Option<u64>,
        excluded_suffix: Option<u64>,
        na_config: &DHCPv6IANAConfig,
    ) -> Option<u64> {
        if self.na_range_capacity == 0 {
            return None;
        }
        let suffix = match self.find_free_dynamic_suffix(duid, excluded_suffix) {
            Some(s) => s,
            None => {
                if self.clean_expired_na().is_empty() {
                    tracing::error!("DHCPv6 NA pool exhausted");
                    return None;
                }
                self.find_free_dynamic_suffix(duid, excluded_suffix)?
            }
        };
        self.insert_dynamic_na_lease(duid, mac, hostname, now, prev_suffix, suffix, na_config);
        Some(suffix)
    }

    fn find_free_dynamic_suffix(&self, duid: &[u8], excluded_suffix: Option<u64>) -> Option<u64> {
        let mut seed = hash_duid(duid);
        for _ in 0..self.na_range_capacity {
            let index = seed % self.na_range_capacity;
            let suffix = self.na_pool_start + index;
            if Some(suffix) != excluded_suffix && !self.na_owners_by_suffix.contains_key(&suffix) {
                return Some(suffix);
            }
            seed = seed.wrapping_add(1);
        }
        None
    }

    fn insert_dynamic_na_lease(
        &mut self,
        duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        now: u64,
        prev_suffix: Option<u64>,
        suffix: u64,
        na_config: &DHCPv6IANAConfig,
    ) {
        self.na_owners_by_suffix.insert(suffix, SuffixOwner::DynamicDuid(duid.to_vec()));
        let lease = NaLease {
            suffix,
            hostname,
            mac,
            duid_hex: duid_to_hex(duid),
            relative_offer_time: now,
            valid_time: OFFER_VALID_TIME,
            preferred_time: na_config.preferred_lifetime.min(OFFER_VALID_TIME),
            is_static: false,
            prev_suffix,
        };
        self.na_leases_by_duid.insert(duid.to_vec(), lease);
    }

    fn remove_dynamic_owner_if_matches(&mut self, suffix: u64, duid: &[u8]) {
        if self.na_owners_by_suffix.get(&suffix) == Some(&SuffixOwner::DynamicDuid(duid.to_vec())) {
            self.na_owners_by_suffix.remove(&suffix);
        }
    }

    fn lease_duid_for_mac(&self, mac: MacAddr) -> Option<Vec<u8>> {
        self.static_lease_duid_for_mac(mac).or_else(|| {
            self.na_leases_by_duid
                .iter()
                .find(|(_, lease)| lease.mac == Some(mac))
                .map(|(duid, _)| duid.clone())
        })
    }

    fn static_lease_duid_for_mac(&self, mac: MacAddr) -> Option<Vec<u8>> {
        self.na_leases_by_duid
            .iter()
            .find(|(_, lease)| lease.mac == Some(mac) && lease.is_static)
            .map(|(duid, _)| duid.clone())
    }

    fn find_free_pd_slot(&self) -> Option<(String, u32)> {
        for range in &self.prefix_state.pd_ranges {
            for idx in range.start_idx..=range.end_idx {
                let key = (range.group_id.clone(), idx);
                if !self.pd_owners_by_slot.contains_key(&key) {
                    return Some(key);
                }
            }
        }
        None
    }

    fn resolve_pd_key(&self, key: &(String, u32)) -> Option<(Ipv6Addr, u8)> {
        pd::resolve_pd_prefix(
            &self.prefix_state.pd_ranges,
            &PdSlotKey { group_id: key.0.clone(), sub_index: key.1 },
        )
    }
}

// ── Utility functions ──────────────────────────────────────────────────────

const OFFER_VALID_TIME: u32 = 120;

fn ipv6_suffix(ip: Ipv6Addr) -> u64 {
    u128::from(ip) as u64
}

fn combine_prefix_suffix(prefix: Ipv6Addr, prefix_len: u8, suffix: u64) -> Ipv6Addr {
    let p = u128::from(prefix);
    let mask = if prefix_len >= 128 { !0u128 } else { !0u128 << (128 - prefix_len) };
    Ipv6Addr::from((p & mask) | (suffix as u128))
}

fn duid_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hash_duid(duid: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &byte in duid {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    hash
}
