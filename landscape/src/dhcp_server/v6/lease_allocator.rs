use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::Instant;

use landscape_common::dhcp::v6_server::config::{
    DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
};
use landscape_common::dhcp::v6_server::status::{
    DHCPv6AddressItem, DHCPv6OfferInfo, DHCPv6PrefixItem,
};
use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;

use super::types::{DHCPv6NACache, DHCPv6PDCache};
use super::utils::{combine_prefix_suffix, compute_delegated_prefix, duid_to_hex, hash_duid};

const OFFER_VALID_TIME: u32 = 120;

pub type NaLease = DHCPv6NACache;
pub type PdLease = DHCPv6PDCache;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuffixOwner {
    StaticMac(MacAddr),
    DynamicDuid(Vec<u8>),
}

pub type NaAllocSource = SuffixOwner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NaAddressCheck {
    Owned,
    NotOnLink,
    Unallocated,
    OwnedByOtherMac(MacAddr),
    OwnedByOtherDuid(Vec<u8>),
}

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
    fn push_allocated(&mut self, lease: NaLease, previous_suffix: Option<u64>) {
        self.allocated.push(NaLeaseChange { lease, previous_suffix });
    }

    fn push_expired(&mut self, lease: NaLease, previous_suffix: Option<u64>) {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdRouteCleanup {
    pub sub_index: u32,
    pub routes: Vec<(Ipv6Addr, u8)>,
}

#[derive(Debug)]
pub struct DhcpV6LeaseAllocator {
    pub boot_time: f64,
    pub relative_boot_time: Instant,
    na: Option<NaSuffixAllocator>,
    pd: Option<PdLeaseAllocator>,
    last_na_prefixes: Vec<(Ipv6Addr, u8)>,
    last_pd_prefixes: Vec<(Ipv6Addr, u8)>,
}

impl DhcpV6LeaseAllocator {
    pub fn from_config_and_devices(
        config: &DHCPv6ServerConfig,
        devices: Vec<EnrolledDevice>,
    ) -> Self {
        Self {
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            na: config.ia_na.clone().map(|config| NaSuffixAllocator::new(config, devices.clone())),
            pd: config.ia_pd.clone().map(PdLeaseAllocator::new),
            last_na_prefixes: Vec::new(),
            last_pd_prefixes: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn init_for_test(config: DHCPv6ServerConfig) -> Self {
        Self::from_config_and_devices(&config, vec![])
    }

    pub fn offer_na(
        &mut self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
    ) -> Option<NaLease> {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.na.as_mut()?.offer(client_duid, mac, hostname, now)
    }

    pub fn confirm_na(&mut self, client_duid: &[u8]) -> bool {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.na.as_mut().is_some_and(|na| na.confirm(client_duid, now))
    }

    pub fn consume_prev_suffix(&mut self, client_duid: &[u8]) {
        if let Some(na) = &mut self.na {
            na.consume_prev_suffix(client_duid);
        }
    }

    pub fn release_na(&mut self, client_duid: &[u8]) -> Option<NaLease> {
        self.na.as_mut()?.release(client_duid)
    }

    pub fn clean_expired_na(&mut self) -> Vec<NaLease> {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.na.as_mut().map(|na| na.clean_expired(now)).unwrap_or_default()
    }

    pub fn bind_mac_suffix(&mut self, mac: MacAddr, suffix: u64) -> MacSuffixBindResult {
        let now = self.relative_boot_time.elapsed().as_secs();
        match &mut self.na {
            Some(na) => na.bind_mac_suffix(mac, suffix, now),
            None => MacSuffixBindResult::InvariantViolation {
                reason: "IA_NA is not configured".to_string(),
            },
        }
    }

    pub fn add_or_update_binding(&mut self, mac: MacAddr, ipv6_addr: Ipv6Addr) {
        let suffix = ipv6_suffix(ipv6_addr);
        let _ = self.bind_mac_suffix(mac, suffix);
    }

    pub fn remove_binding(&mut self, mac: &MacAddr) -> LeaseChangeSet {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.na.as_mut().map(|na| na.remove_mac_binding(mac, now)).unwrap_or_default()
    }

    pub fn get_na_offer(&self, client_duid: &[u8]) -> Option<NaLease> {
        self.na.as_ref()?.leases_by_duid.get(client_duid).cloned()
    }

    pub fn has_na_offer(&self, client_duid: &[u8]) -> bool {
        self.na.as_ref().is_some_and(|na| na.leases_by_duid.contains_key(client_duid))
    }

    pub fn get_na_by_mac(&self, mac: MacAddr) -> Option<NaLease> {
        self.na.as_ref()?.lease_for_mac(mac).cloned()
    }

    pub fn get_suffix_owner(&self, suffix: u64) -> Option<SuffixOwner> {
        self.na.as_ref()?.owners_by_suffix.get(&suffix).cloned()
    }

    pub fn check_na_address_owner(
        &self,
        ip: Ipv6Addr,
        na_prefixes: &[(Ipv6Addr, u8)],
        client_duid: &[u8],
        mac: Option<MacAddr>,
    ) -> NaAddressCheck {
        let Some(na) = &self.na else {
            return NaAddressCheck::Unallocated;
        };
        if !is_on_link(ip, na_prefixes) {
            return NaAddressCheck::NotOnLink;
        }
        na.check_suffix_owner(ipv6_suffix(ip), client_duid, mac)
    }

    pub fn offer_pd_index(
        &mut self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
    ) -> Option<u32> {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.pd.as_mut()?.offer(client_duid, qualifying_prefixes, now).map(|lease| lease.sub_index)
    }

    pub fn confirm_pd(&mut self, client_duid: &[u8]) -> bool {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.pd.as_mut().is_some_and(|pd| pd.confirm(client_duid, now))
    }

    pub fn release_pd(&mut self, client_duid: &[u8]) -> Option<PdLease> {
        self.pd.as_mut()?.release(client_duid)
    }

    pub fn clean_expired_pd(&mut self) -> Vec<PdLease> {
        let now = self.relative_boot_time.elapsed().as_secs();
        self.pd.as_mut().map(|pd| pd.clean_expired(now)).unwrap_or_default()
    }

    pub fn get_pd_offer(&self, client_duid: &[u8]) -> Option<PdLease> {
        self.pd.as_ref()?.leases_by_duid.get(client_duid).cloned()
    }

    pub fn has_pd_offer(&self, client_duid: &[u8]) -> bool {
        self.pd.as_ref().is_some_and(|pd| pd.leases_by_duid.contains_key(client_duid))
    }

    pub fn get_pd_route_info(&self, client_duid: &[u8]) -> Option<(Vec<(Ipv6Addr, u8)>, u32, u32)> {
        self.pd
            .as_ref()?
            .leases_by_duid
            .get(client_duid)
            .map(|lease| (lease.active_routes.clone(), lease.sub_index, lease.valid_time))
    }

    pub fn update_pd_active_routes(
        &mut self,
        client_duid: &[u8],
        client_addr: Ipv6Addr,
        routes: Vec<(Ipv6Addr, u8)>,
    ) -> Option<Vec<(Ipv6Addr, u8)>> {
        self.pd.as_mut()?.update_active_routes(client_duid, client_addr, routes)
    }

    pub fn reconcile_pd_routes(
        &mut self,
        current_pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> Vec<PdRouteCleanup> {
        self.pd
            .as_mut()
            .map(|pd| pd.reconcile_active_routes(current_pd_prefixes))
            .unwrap_or_default()
    }

    pub fn lease_view(
        &self,
        na_prefixes: &[(Ipv6Addr, u8)],
        pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> DHCPv6OfferInfo {
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();
        let mut offered_addresses = Vec::new();
        if let Some(na) = &self.na {
            for lease in na.leases_by_duid.values() {
                for (prefix, prefix_len) in na_prefixes {
                    offered_addresses.push(DHCPv6AddressItem {
                        duid: Some(lease.duid_hex.clone()),
                        mac: lease.mac,
                        ip: combine_prefix_suffix(*prefix, *prefix_len, lease.suffix),
                        hostname: lease.hostname.clone(),
                        relative_active_time: lease.relative_offer_time,
                        preferred_lifetime: lease.preferred_time,
                        valid_lifetime: lease.valid_time,
                        is_static: lease.is_static,
                        prev_suffix: lease.prev_suffix,
                    });
                }
            }
        }

        let mut delegated_prefixes = Vec::new();
        if let Some(pd) = &self.pd {
            for lease in pd.leases_by_duid.values() {
                if let Some((base_prefix, base_prefix_len)) =
                    pd_prefixes.get(lease.sub_index as usize)
                {
                    delegated_prefixes.push(DHCPv6PrefixItem {
                        duid: Some(lease.duid_hex.clone()),
                        prefix: compute_delegated_prefix(
                            *base_prefix,
                            *base_prefix_len,
                            *base_prefix_len,
                            0,
                        ),
                        prefix_len: *base_prefix_len,
                        relative_active_time: lease.relative_offer_time,
                        preferred_lifetime: lease.preferred_time,
                        valid_lifetime: lease.valid_time,
                    });
                }
            }
        }

        DHCPv6OfferInfo {
            boot_time: self.boot_time,
            relative_boot_time,
            offered_addresses,
            delegated_prefixes,
        }
    }

    pub fn set_prefixes(
        &mut self,
        na_prefixes: Vec<(Ipv6Addr, u8)>,
        pd_prefixes: Vec<(Ipv6Addr, u8)>,
    ) {
        self.last_na_prefixes = na_prefixes;
        self.last_pd_prefixes = pd_prefixes;
    }

    pub fn lease_view_with_last_prefixes(&self) -> DHCPv6OfferInfo {
        self.lease_view(&self.last_na_prefixes, &self.last_pd_prefixes)
    }

    pub fn static_binding_view_with_last_prefixes(&self) -> Vec<(MacAddr, Ipv6Addr)> {
        let Some(na) = &self.na else {
            return Vec::new();
        };
        let Some((prefix, prefix_len)) = self.last_na_prefixes.first() else {
            return Vec::new();
        };
        na.static_suffix_by_mac
            .iter()
            .map(|(mac, suffix)| (*mac, combine_prefix_suffix(*prefix, *prefix_len, *suffix)))
            .collect()
    }
}

#[derive(Debug)]
struct NaSuffixAllocator {
    config: DHCPv6IANAConfig,
    pool_start: u64,
    range_capacity: u64,
    leases_by_duid: HashMap<Vec<u8>, NaLease>,
    owners_by_suffix: HashMap<u64, SuffixOwner>,
    static_suffix_by_mac: HashMap<MacAddr, u64>,
}

impl NaSuffixAllocator {
    fn new(config: DHCPv6IANAConfig, devices: Vec<EnrolledDevice>) -> Self {
        let end = config.pool_end.unwrap_or(config.pool_start + 0xFFFF);
        let mut allocator = Self {
            pool_start: config.pool_start,
            range_capacity: end - config.pool_start,
            config,
            leases_by_duid: HashMap::new(),
            owners_by_suffix: HashMap::new(),
            static_suffix_by_mac: HashMap::new(),
        };
        for device in devices {
            if let Some(ipv6) = device.ipv6 {
                let suffix = ipv6_suffix(ipv6);
                allocator.static_suffix_by_mac.insert(device.mac, suffix);
                allocator.owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(device.mac));
            }
        }
        allocator
    }

    fn offer(
        &mut self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        now: u64,
    ) -> Option<NaLease> {
        if let Some(mac) = mac {
            if let Some(&suffix) = self.static_suffix_by_mac.get(&mac) {
                return Some(self.assign_static(client_duid, mac, suffix, hostname, now));
            }
        }

        if let Some(lease) = self.leases_by_duid.get(client_duid) {
            return Some(lease.clone());
        }

        self.allocate_dynamic(client_duid, mac, hostname, now, None, None)
    }

    fn assign_static(
        &mut self,
        client_duid: &[u8],
        mac: MacAddr,
        suffix: u64,
        hostname: Option<String>,
        now: u64,
    ) -> NaLease {
        let previous_suffix = self.leases_by_duid.get(client_duid).map(|lease| lease.suffix);
        if let Some(old) = previous_suffix {
            self.remove_dynamic_owner_if_matches(old, client_duid);
        }
        if let Some(old_duid) = self.static_lease_duid_for_mac(mac) {
            if old_duid != client_duid {
                self.leases_by_duid.remove(&old_duid);
            }
        }
        self.owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(mac));
        let lease = NaLease {
            suffix,
            hostname,
            mac: Some(mac),
            duid_hex: duid_to_hex(client_duid),
            relative_offer_time: now,
            valid_time: self.config.valid_lifetime,
            preferred_time: self.config.preferred_lifetime,
            is_static: true,
            prev_suffix: previous_suffix.filter(|previous| *previous != suffix),
        };
        self.leases_by_duid.insert(client_duid.to_vec(), lease.clone());
        lease
    }

    fn confirm(&mut self, client_duid: &[u8], now: u64) -> bool {
        if let Some(lease) = self.leases_by_duid.get_mut(client_duid) {
            if !lease.is_static {
                lease.valid_time = self.config.valid_lifetime;
            }
            lease.preferred_time = self.config.preferred_lifetime;
            lease.relative_offer_time = now;
            true
        } else {
            false
        }
    }

    fn consume_prev_suffix(&mut self, client_duid: &[u8]) {
        if let Some(lease) = self.leases_by_duid.get_mut(client_duid) {
            lease.prev_suffix = None;
        }
    }

    fn release(&mut self, client_duid: &[u8]) -> Option<NaLease> {
        let lease = self.leases_by_duid.remove(client_duid)?;
        if !lease.is_static {
            self.remove_dynamic_owner_if_matches(lease.suffix, client_duid);
        }
        Some(lease)
    }

    fn clean_expired(&mut self, now: u64) -> Vec<NaLease> {
        let expired_duids: Vec<Vec<u8>> = self
            .leases_by_duid
            .iter()
            .filter(|(_, lease)| {
                !lease.is_static && now > lease.relative_offer_time + lease.valid_time as u64
            })
            .map(|(duid, _)| duid.clone())
            .collect();
        let mut expired = Vec::new();
        for duid in expired_duids {
            if let Some(lease) = self.release(&duid) {
                expired.push(lease);
            }
        }
        expired
    }

    fn bind_mac_suffix(&mut self, mac: MacAddr, suffix: u64, now: u64) -> MacSuffixBindResult {
        if self.static_suffix_by_mac.get(&mac) == Some(&suffix)
            && self.owners_by_suffix.get(&suffix) == Some(&SuffixOwner::StaticMac(mac))
        {
            return MacSuffixBindResult::AlreadyBound;
        }

        match self.owners_by_suffix.get(&suffix).cloned() {
            Some(SuffixOwner::StaticMac(owner)) if owner != mac => {
                return MacSuffixBindResult::StaticConflict { owner };
            }
            _ => {}
        }

        let old_static_suffix = self.static_suffix_by_mac.get(&mac).copied();
        if let Some(old_suffix) = old_static_suffix {
            match self.owners_by_suffix.get(&old_suffix) {
                Some(SuffixOwner::StaticMac(owner)) if *owner == mac => {}
                Some(_) => {
                    return MacSuffixBindResult::InvariantViolation {
                        reason: format!(
                            "static suffix {old_suffix} for {mac} is owned by another source"
                        ),
                    };
                }
                None => {}
            }
        }

        let mut changes = LeaseChangeSet::default();
        let mac_duid = self.lease_duid_for_mac(mac);

        self.static_suffix_by_mac.insert(mac, suffix);
        if let Some(old_suffix) = old_static_suffix.filter(|old| *old != suffix) {
            if self.owners_by_suffix.get(&old_suffix) == Some(&SuffixOwner::StaticMac(mac)) {
                self.owners_by_suffix.remove(&old_suffix);
            }
        }

        if let Some(duid) = &mac_duid {
            if let Some(previous) = self.leases_by_duid.get(duid).map(|lease| lease.suffix) {
                self.remove_dynamic_owner_if_matches(previous, duid);
            }
        }

        if let Some(SuffixOwner::DynamicDuid(evicted_duid)) = self.owners_by_suffix.remove(&suffix)
        {
            if mac_duid.as_ref() != Some(&evicted_duid) {
                if let Some(mut evicted) = self.leases_by_duid.remove(&evicted_duid) {
                    changes.push_expired(evicted.clone(), Some(suffix));
                    if let Some(old_suffix) = old_static_suffix
                        .filter(|old| *old != suffix && self.is_dynamic_pool_suffix(*old))
                    {
                        evicted.prev_suffix = Some(suffix);
                        evicted.suffix = old_suffix;
                        evicted.is_static = false;
                        evicted.relative_offer_time = now;
                        evicted.valid_time = OFFER_VALID_TIME;
                        evicted.preferred_time =
                            self.config.preferred_lifetime.min(OFFER_VALID_TIME);
                        self.owners_by_suffix
                            .insert(old_suffix, SuffixOwner::DynamicDuid(evicted_duid.clone()));
                        self.leases_by_duid.insert(evicted_duid, evicted.clone());
                        changes.push_allocated(evicted, Some(suffix));
                    } else if let Some(reassigned) = self.allocate_dynamic(
                        &evicted_duid,
                        evicted.mac,
                        evicted.hostname.clone(),
                        now,
                        Some(suffix),
                        Some(suffix),
                    ) {
                        changes.push_allocated(reassigned, Some(suffix));
                    } else {
                        changes.released.push(evicted);
                    }
                }
            }
        }

        self.owners_by_suffix.insert(suffix, SuffixOwner::StaticMac(mac));
        if let Some(duid) = mac_duid {
            if let Some(lease) = self.leases_by_duid.get_mut(&duid) {
                let previous = lease.suffix;
                lease.suffix = suffix;
                lease.is_static = true;
                lease.prev_suffix = (previous != suffix).then_some(previous);
                lease.relative_offer_time = now;
                lease.valid_time = self.config.valid_lifetime;
                lease.preferred_time = self.config.preferred_lifetime;
                changes.push_allocated(lease.clone(), (previous != suffix).then_some(previous));
            }
        }

        MacSuffixBindResult::Bound(changes)
    }

    fn remove_mac_binding(&mut self, mac: &MacAddr, now: u64) -> LeaseChangeSet {
        let Some(old_suffix) = self.static_suffix_by_mac.remove(mac) else {
            return LeaseChangeSet::default();
        };
        if self.owners_by_suffix.get(&old_suffix) == Some(&SuffixOwner::StaticMac(*mac)) {
            self.owners_by_suffix.remove(&old_suffix);
        }
        let Some(duid) = self.static_lease_duid_for_mac(*mac) else {
            return LeaseChangeSet::default();
        };
        let Some(mut lease) = self.leases_by_duid.remove(&duid) else {
            return LeaseChangeSet::default();
        };

        let mut changes = LeaseChangeSet::default();
        changes.push_expired(lease.clone(), Some(old_suffix));
        if self.is_dynamic_pool_suffix(old_suffix)
            && !self.owners_by_suffix.contains_key(&old_suffix)
        {
            lease.is_static = false;
            lease.prev_suffix = Some(old_suffix);
            lease.relative_offer_time = now;
            lease.valid_time = self.config.valid_lifetime;
            lease.preferred_time = self.config.preferred_lifetime;
            self.owners_by_suffix.insert(old_suffix, SuffixOwner::DynamicDuid(duid.clone()));
            self.leases_by_duid.insert(duid, lease.clone());
            changes.push_allocated(lease, Some(old_suffix));
        } else if let Some(reassigned) = self.allocate_dynamic(
            &duid,
            lease.mac,
            lease.hostname.clone(),
            now,
            Some(old_suffix),
            None,
        ) {
            changes.push_allocated(reassigned, Some(old_suffix));
        } else {
            changes.released.push(lease);
        }
        changes
    }

    fn check_suffix_owner(
        &self,
        suffix: u64,
        client_duid: &[u8],
        mac: Option<MacAddr>,
    ) -> NaAddressCheck {
        match self.owners_by_suffix.get(&suffix) {
            Some(SuffixOwner::StaticMac(owner)) => {
                if Some(*owner) == mac {
                    NaAddressCheck::Owned
                } else {
                    NaAddressCheck::OwnedByOtherMac(*owner)
                }
            }
            Some(SuffixOwner::DynamicDuid(owner)) => {
                if owner == client_duid {
                    NaAddressCheck::Owned
                } else {
                    NaAddressCheck::OwnedByOtherDuid(owner.clone())
                }
            }
            None => NaAddressCheck::Unallocated,
        }
    }

    fn allocate_dynamic(
        &mut self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        now: u64,
        prev_suffix: Option<u64>,
        excluded_suffix: Option<u64>,
    ) -> Option<NaLease> {
        if self.range_capacity == 0 {
            return None;
        }
        let suffix = match self.find_free_dynamic_suffix(client_duid, excluded_suffix) {
            Some(suffix) => suffix,
            None => {
                if self.clean_expired(now).is_empty() {
                    tracing::error!("DHCPv6 NA pool is full");
                    return None;
                }
                self.find_free_dynamic_suffix(client_duid, excluded_suffix)?
            }
        };
        Some(self.insert_dynamic_lease(client_duid, mac, hostname, now, prev_suffix, suffix))
    }

    fn find_free_dynamic_suffix(
        &self,
        client_duid: &[u8],
        excluded_suffix: Option<u64>,
    ) -> Option<u64> {
        let mut seed = hash_duid(client_duid);
        for _ in 0..self.range_capacity {
            let index = seed % self.range_capacity;
            let suffix = self.pool_start + index;
            if Some(suffix) != excluded_suffix && !self.owners_by_suffix.contains_key(&suffix) {
                return Some(suffix);
            }
            seed = seed.wrapping_add(1);
        }
        None
    }

    fn insert_dynamic_lease(
        &mut self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
        now: u64,
        prev_suffix: Option<u64>,
        suffix: u64,
    ) -> NaLease {
        self.owners_by_suffix.insert(suffix, SuffixOwner::DynamicDuid(client_duid.to_vec()));
        let lease = NaLease {
            suffix,
            hostname,
            mac,
            duid_hex: duid_to_hex(client_duid),
            relative_offer_time: now,
            valid_time: OFFER_VALID_TIME,
            preferred_time: self.config.preferred_lifetime.min(OFFER_VALID_TIME),
            is_static: false,
            prev_suffix,
        };
        self.leases_by_duid.insert(client_duid.to_vec(), lease.clone());
        lease
    }

    fn remove_dynamic_owner_if_matches(&mut self, suffix: u64, client_duid: &[u8]) {
        if self.owners_by_suffix.get(&suffix)
            == Some(&SuffixOwner::DynamicDuid(client_duid.to_vec()))
        {
            self.owners_by_suffix.remove(&suffix);
        }
    }

    fn lease_duid_for_mac(&self, mac: MacAddr) -> Option<Vec<u8>> {
        if let Some(duid) = self.static_lease_duid_for_mac(mac) {
            return Some(duid);
        }
        self.leases_by_duid
            .iter()
            .find(|(_, lease)| lease.mac == Some(mac))
            .map(|(duid, _)| duid.clone())
    }

    fn static_lease_duid_for_mac(&self, mac: MacAddr) -> Option<Vec<u8>> {
        self.leases_by_duid
            .iter()
            .find(|(_, lease)| lease.mac == Some(mac) && lease.is_static)
            .map(|(duid, _)| duid.clone())
    }

    fn lease_for_mac(&self, mac: MacAddr) -> Option<&NaLease> {
        self.leases_by_duid
            .values()
            .find(|lease| lease.mac == Some(mac) && lease.is_static)
            .or_else(|| self.leases_by_duid.values().find(|lease| lease.mac == Some(mac)))
    }

    fn is_dynamic_pool_suffix(&self, suffix: u64) -> bool {
        suffix >= self.pool_start && suffix < self.pool_start + self.range_capacity
    }
}

#[derive(Debug)]
struct PdLeaseAllocator {
    config: DHCPv6IAPDConfig,
    leases_by_duid: HashMap<Vec<u8>, PdLease>,
    owners_by_slot: HashMap<u32, Vec<u8>>,
}

impl PdLeaseAllocator {
    fn new(config: DHCPv6IAPDConfig) -> Self {
        Self {
            config,
            leases_by_duid: HashMap::new(),
            owners_by_slot: HashMap::new(),
        }
    }

    fn offer(
        &mut self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
        now: u64,
    ) -> Option<PdLease> {
        if qualifying_prefixes.is_empty() {
            return None;
        }
        if let Some(lease) = self.leases_by_duid.get(client_duid) {
            if (lease.sub_index as usize) < qualifying_prefixes.len() {
                return Some(lease.clone());
            }
            let lease = self.leases_by_duid.remove(client_duid).expect("lease exists");
            self.owners_by_slot.remove(&lease.sub_index);
        }

        let slots = qualifying_prefixes.len() as u32;
        let slot = match self.first_free_slot(slots) {
            Some(slot) => slot,
            None => {
                if self.clean_expired(now).is_empty() {
                    tracing::warn!(
                        "DHCPv6 PD pool exhausted ({} slots)",
                        qualifying_prefixes.len()
                    );
                    return None;
                }
                match self.first_free_slot(slots) {
                    Some(slot) => slot,
                    None => {
                        tracing::warn!(
                            "DHCPv6 PD pool exhausted after cleanup ({} slots)",
                            qualifying_prefixes.len()
                        );
                        return None;
                    }
                }
            }
        };
        self.owners_by_slot.insert(slot, client_duid.to_vec());
        let lease = PdLease {
            sub_index: slot,
            duid_hex: duid_to_hex(client_duid),
            relative_offer_time: now,
            valid_time: OFFER_VALID_TIME,
            preferred_time: self.config.preferred_lifetime.min(OFFER_VALID_TIME),
            client_addr: Ipv6Addr::UNSPECIFIED,
            active_routes: Vec::new(),
        };
        self.leases_by_duid.insert(client_duid.to_vec(), lease.clone());
        Some(lease)
    }

    fn confirm(&mut self, client_duid: &[u8], now: u64) -> bool {
        if let Some(lease) = self.leases_by_duid.get_mut(client_duid) {
            lease.valid_time = self.config.valid_lifetime;
            lease.preferred_time = self.config.preferred_lifetime;
            lease.relative_offer_time = now;
            true
        } else {
            false
        }
    }

    fn release(&mut self, client_duid: &[u8]) -> Option<PdLease> {
        let lease = self.leases_by_duid.remove(client_duid)?;
        self.owners_by_slot.remove(&lease.sub_index);
        Some(lease)
    }

    fn clean_expired(&mut self, now: u64) -> Vec<PdLease> {
        let expired_duids: Vec<Vec<u8>> = self
            .leases_by_duid
            .iter()
            .filter(|(_, lease)| now > lease.relative_offer_time + lease.valid_time as u64)
            .map(|(duid, _)| duid.clone())
            .collect();
        let mut expired = Vec::new();
        for duid in expired_duids {
            if let Some(lease) = self.release(&duid) {
                expired.push(lease);
            }
        }
        expired
    }

    fn update_active_routes(
        &mut self,
        client_duid: &[u8],
        client_addr: Ipv6Addr,
        routes: Vec<(Ipv6Addr, u8)>,
    ) -> Option<Vec<(Ipv6Addr, u8)>> {
        let lease = self.leases_by_duid.get_mut(client_duid)?;
        let old_routes = std::mem::replace(&mut lease.active_routes, routes);
        lease.client_addr = client_addr;
        Some(old_routes)
    }

    fn reconcile_active_routes(
        &mut self,
        current_pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> Vec<PdRouteCleanup> {
        let mut cleanups = Vec::new();
        for lease in self.leases_by_duid.values_mut() {
            if lease.active_routes.is_empty() {
                continue;
            }

            let expected_route =
                current_pd_prefixes.get(lease.sub_index as usize).map(|(prefix, prefix_len)| {
                    (compute_delegated_prefix(*prefix, *prefix_len, *prefix_len, 0), *prefix_len)
                });

            let route_is_current = expected_route
                .map(|expected| {
                    lease.active_routes.len() == 1 && lease.active_routes[0] == expected
                })
                .unwrap_or(false);

            if !route_is_current {
                cleanups.push(PdRouteCleanup {
                    sub_index: lease.sub_index,
                    routes: std::mem::take(&mut lease.active_routes),
                });
            }
        }
        cleanups
    }

    fn first_free_slot(&self, slots: u32) -> Option<u32> {
        (0..slots).find(|idx| !self.owners_by_slot.contains_key(idx))
    }
}

fn ipv6_suffix(ip: Ipv6Addr) -> u64 {
    u128::from(ip) as u64
}

fn is_on_link(ip: Ipv6Addr, prefixes: &[(Ipv6Addr, u8)]) -> bool {
    prefixes.iter().any(|(prefix, prefix_len)| {
        let mask = if *prefix_len >= 128 { !0u128 } else { !0u128 << (128 - prefix_len) };
        (u128::from(ip) & mask) == (u128::from(*prefix) & mask)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::dhcp::v6_server::config::{
        DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
    };

    fn config(pool_start: u64, pool_end: u64) -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start,
                pool_end: Some(pool_end),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        }
    }

    fn pd_config() -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            enable: true,
            ia_na: None,
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 56,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        }
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::from([0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    fn device(mac: MacAddr, suffix: u16) -> EnrolledDevice {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "mac": mac.to_string(),
            "name": "test-device",
            "iface_name": "lan0",
            "ipv4": null,
            "ipv6": Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, suffix).to_string(),
        }))
        .unwrap()
    }

    #[test]
    fn bind_mac_suffix_swaps_old_static_suffix_to_dynamic_owner() {
        let static_mac = mac(1);
        let dynamic_mac = mac(2);
        let static_suffix = 0x101;
        let cfg = config(0x100, 0x104);
        let mut allocator =
            DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![device(static_mac, 0x101)]);

        let dynamic_duid = b"dynamic-client";
        let dynamic_lease = allocator.offer_na(dynamic_duid, Some(dynamic_mac), None).unwrap();
        let dynamic_suffix = dynamic_lease.suffix;
        assert_ne!(dynamic_suffix, static_suffix);

        let result = allocator.bind_mac_suffix(static_mac, dynamic_suffix);
        assert!(matches!(result, MacSuffixBindResult::Bound(_)));

        assert_eq!(
            allocator.get_suffix_owner(dynamic_suffix),
            Some(SuffixOwner::StaticMac(static_mac))
        );
        assert_eq!(
            allocator.get_suffix_owner(static_suffix),
            Some(SuffixOwner::DynamicDuid(dynamic_duid.to_vec()))
        );
        let reassigned = allocator.get_na_offer(dynamic_duid).unwrap();
        assert_eq!(reassigned.suffix, static_suffix);
        assert_eq!(reassigned.prev_suffix, Some(dynamic_suffix));
    }

    #[test]
    fn bind_mac_suffix_releases_dynamic_when_pool_has_no_replacement() {
        let cfg = config(0x100, 0x101);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let dynamic_duid = b"dynamic-client";
        let dynamic_mac = mac(3);
        let dynamic_suffix =
            allocator.offer_na(dynamic_duid, Some(dynamic_mac), None).unwrap().suffix;

        let static_mac = mac(4);
        let result = allocator.bind_mac_suffix(static_mac, dynamic_suffix);
        let MacSuffixBindResult::Bound(changes) = result else {
            panic!("expected successful static bind");
        };

        assert_eq!(
            allocator.get_suffix_owner(dynamic_suffix),
            Some(SuffixOwner::StaticMac(static_mac))
        );
        assert!(allocator.get_na_offer(dynamic_duid).is_none());
        assert_eq!(changes.released.len(), 1);
    }

    #[test]
    fn bind_mac_suffix_for_dynamic_mac_releases_previous_dynamic_suffix() {
        let cfg = config(0x100, 0x110);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let client_duid = b"dynamic-client";
        let client_mac = mac(5);
        let old_suffix = allocator.offer_na(client_duid, Some(client_mac), None).unwrap().suffix;
        let new_suffix = if old_suffix == 0x100 { 0x101 } else { 0x100 };

        let result = allocator.bind_mac_suffix(client_mac, new_suffix);
        assert!(matches!(result, MacSuffixBindResult::Bound(_)));

        assert_eq!(allocator.get_suffix_owner(old_suffix), None);
        assert_eq!(
            allocator.get_suffix_owner(new_suffix),
            Some(SuffixOwner::StaticMac(client_mac))
        );
        let lease = allocator.get_na_offer(client_duid).unwrap();
        assert_eq!(lease.suffix, new_suffix);
        assert_eq!(lease.prev_suffix, Some(old_suffix));
        assert!(lease.is_static);
    }

    #[test]
    fn bind_mac_suffix_moves_evicted_dynamic_to_callers_old_dynamic_suffix() {
        let cfg = config(0x100, 0x102);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let mac_a = mac(6);
        let mac_b = mac(7);
        let duid_a = b"client-a";
        let duid_b = b"client-b";
        let suffix_a = allocator.offer_na(duid_a, Some(mac_a), None).unwrap().suffix;
        let suffix_b = allocator.offer_na(duid_b, Some(mac_b), None).unwrap().suffix;
        assert_ne!(suffix_a, suffix_b);

        let result = allocator.bind_mac_suffix(mac_a, suffix_b);
        assert!(matches!(result, MacSuffixBindResult::Bound(_)));

        assert_eq!(allocator.get_suffix_owner(suffix_b), Some(SuffixOwner::StaticMac(mac_a)));
        assert_eq!(
            allocator.get_suffix_owner(suffix_a),
            Some(SuffixOwner::DynamicDuid(duid_b.to_vec()))
        );
        let lease_a = allocator.get_na_offer(duid_a).unwrap();
        assert_eq!(lease_a.suffix, suffix_b);
        assert!(lease_a.is_static);
        let lease_b = allocator.get_na_offer(duid_b).unwrap();
        assert_eq!(lease_b.suffix, suffix_a);
        assert_eq!(lease_b.prev_suffix, Some(suffix_b));
    }

    #[test]
    fn static_suffix_outside_dynamic_pool_does_not_exhaust_pool() {
        let static_mac = mac(8);
        let cfg = config(0x100, 0x101);
        let mut allocator =
            DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![device(static_mac, 0x200)]);

        let lease = allocator.offer_na(b"dynamic-client", Some(mac(9)), None).unwrap();

        assert_eq!(lease.suffix, 0x100);
        assert_eq!(allocator.get_suffix_owner(0x200), Some(SuffixOwner::StaticMac(static_mac)));
    }

    #[test]
    fn offer_na_cleans_expired_lease_when_pool_is_full() {
        let cfg = config(0x100, 0x101);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let duid_a = b"client-a".to_vec();
        let duid_b = b"client-b".to_vec();

        let first = allocator.offer_na(&duid_a, Some(mac(11)), None).unwrap();
        assert_eq!(first.suffix, 0x100);
        {
            let na = allocator.na.as_mut().unwrap();
            let lease = na.leases_by_duid.get_mut(&duid_a).unwrap();
            lease.relative_offer_time = 0;
            lease.valid_time = 0;
        }
        allocator.relative_boot_time =
            std::time::Instant::now() - std::time::Duration::from_secs(1);

        let second = allocator.offer_na(&duid_b, Some(mac(12)), None).unwrap();

        assert_eq!(second.suffix, 0x100);
        assert!(allocator.get_na_offer(&duid_a).is_none());
        assert_eq!(allocator.get_suffix_owner(0x100), Some(SuffixOwner::DynamicDuid(duid_b)));
    }

    #[test]
    fn offer_na_pool_full_without_expired_lease_returns_none() {
        let cfg = config(0x100, 0x101);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);

        assert!(allocator.offer_na(b"client-a", Some(mac(13)), None).is_some());
        assert!(allocator.offer_na(b"client-b", Some(mac(14)), None).is_none());
    }

    #[test]
    fn offer_pd_cleans_expired_lease_when_pool_is_full() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let qualifying_prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56)];
        let duid_a = b"client-a".to_vec();
        let duid_b = b"client-b".to_vec();

        assert_eq!(allocator.offer_pd_index(&duid_a, &qualifying_prefixes), Some(0));
        {
            let pd = allocator.pd.as_mut().unwrap();
            let lease = pd.leases_by_duid.get_mut(&duid_a).unwrap();
            lease.relative_offer_time = 0;
            lease.valid_time = 0;
        }
        allocator.relative_boot_time =
            std::time::Instant::now() - std::time::Duration::from_secs(1);

        assert_eq!(allocator.offer_pd_index(&duid_b, &qualifying_prefixes), Some(0));
        assert!(allocator.get_pd_offer(&duid_a).is_none());
        assert_eq!(allocator.get_pd_offer(&duid_b).unwrap().sub_index, 0);
    }

    #[test]
    fn offer_pd_pool_full_without_expired_lease_returns_none() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let qualifying_prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56)];

        assert_eq!(allocator.offer_pd_index(b"client-a", &qualifying_prefixes), Some(0));
        assert_eq!(allocator.offer_pd_index(b"client-b", &qualifying_prefixes), None);
    }

    #[test]
    fn offer_pd_reallocates_stale_slot_when_prefixes_shrink() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let two_prefixes = [
            (Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56),
            (Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 56),
        ];
        let one_prefix = [two_prefixes[0]];

        assert_eq!(allocator.offer_pd_index(b"client-a", &two_prefixes), Some(0));
        assert_eq!(allocator.offer_pd_index(b"client-b", &two_prefixes), Some(1));
        allocator.release_pd(b"client-a");

        assert_eq!(allocator.offer_pd_index(b"client-b", &one_prefix), Some(0));
        assert_eq!(allocator.get_pd_offer(b"client-b").unwrap().sub_index, 0);
    }

    #[test]
    fn reconcile_pd_routes_keeps_current_active_route() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56)];
        let route = (compute_delegated_prefix(prefixes[0].0, prefixes[0].1, prefixes[0].1, 0), 56);

        assert_eq!(allocator.offer_pd_index(b"client-a", &prefixes), Some(0));
        allocator.update_pd_active_routes(b"client-a", Ipv6Addr::LOCALHOST, vec![route]);

        let cleanups = allocator.reconcile_pd_routes(&prefixes);

        assert!(cleanups.is_empty());
        assert_eq!(allocator.get_pd_offer(b"client-a").unwrap().active_routes, vec![route]);
    }

    #[test]
    fn reconcile_pd_routes_clears_changed_active_route() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let old_prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56)];
        let new_prefixes = [(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 56)];
        let old_route = (
            compute_delegated_prefix(old_prefixes[0].0, old_prefixes[0].1, old_prefixes[0].1, 0),
            56,
        );

        assert_eq!(allocator.offer_pd_index(b"client-a", &old_prefixes), Some(0));
        allocator.update_pd_active_routes(b"client-a", Ipv6Addr::LOCALHOST, vec![old_route]);

        let cleanups = allocator.reconcile_pd_routes(&new_prefixes);

        assert_eq!(cleanups, vec![PdRouteCleanup { sub_index: 0, routes: vec![old_route] }]);
        assert!(allocator.get_pd_offer(b"client-a").unwrap().active_routes.is_empty());
    }

    #[test]
    fn reconcile_pd_routes_clears_routes_for_missing_slot() {
        let cfg = pd_config();
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let prefixes = [
            (Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 56),
            (Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 56),
        ];
        let route = (compute_delegated_prefix(prefixes[1].0, prefixes[1].1, prefixes[1].1, 0), 56);

        assert_eq!(allocator.offer_pd_index(b"client-a", &prefixes), Some(0));
        assert_eq!(allocator.offer_pd_index(b"client-b", &prefixes), Some(1));
        allocator.update_pd_active_routes(b"client-b", Ipv6Addr::LOCALHOST, vec![route]);

        let cleanups = allocator.reconcile_pd_routes(&prefixes[..1]);

        assert_eq!(cleanups, vec![PdRouteCleanup { sub_index: 1, routes: vec![route] }]);
        assert!(allocator.get_pd_offer(b"client-b").unwrap().active_routes.is_empty());
    }

    #[test]
    fn lease_view_projects_suffixes_through_current_prefixes() {
        let cfg = config(0x100, 0x110);
        let mut allocator = DhcpV6LeaseAllocator::from_config_and_devices(&cfg, vec![]);
        let duid = b"client";
        let suffix = allocator.offer_na(duid, Some(mac(10)), None).unwrap().suffix;
        let prefix = Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 0);

        let view = allocator.lease_view(&[(prefix, 64)], &[]);

        assert_eq!(view.offered_addresses.len(), 1);
        assert_eq!(view.offered_addresses[0].ip, combine_prefix_suffix(prefix, 64, suffix));
    }
}
