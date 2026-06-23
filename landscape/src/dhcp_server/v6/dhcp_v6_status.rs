use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use landscape_common::dhcp::v6_server::config::{
    DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
};
use landscape_common::dhcp::v6_server::status::{
    DHCPv6AddressItem, DHCPv6OfferInfo, DHCPv6PrefixItem,
};
use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;

use crate::dhcp_server::v6::types::{DHCPv6NACache, DHCPv6PDCache};
use crate::dhcp_server::v6::utils::{
    combine_prefix_suffix, compute_delegated_prefix, duid_to_hex, hash_duid,
};
use crate::ipv6::prefix::{ICMPv6ConfigInfo, PdDelegationParent};

const OFFER_VALID_TIME: u32 = 120;

#[derive(Debug)]
pub struct DhcpV6AssignStatus {
    pub boot_time: f64,
    pub relative_boot_time: Instant,

    pub na_config: Option<DHCPv6IANAConfig>,
    pub na_pool_start: u64,
    pub na_range_capacity: u64,
    pub na_allocated_suffixes: HashMap<u64, bool>,
    pub na_offered: HashMap<Vec<u8>, DHCPv6NACache>,

    pub pd_config: Option<DHCPv6IAPDConfig>,
    pub pd_pool_start: u32,
    pub pd_range_capacity: u32,
    pub pd_allocated_indices: HashMap<u32, bool>,
    pub pd_offered: HashMap<Vec<u8>, DHCPv6PDCache>,

    pub static_bindings: HashMap<MacAddr, Ipv6Addr>,
    pub last_offer_info: DHCPv6OfferInfo,
}

impl DhcpV6AssignStatus {
    pub fn from_config_and_devices(
        config: &DHCPv6ServerConfig,
        devices: Vec<EnrolledDevice>,
    ) -> Self {
        let (na_pool_start, na_range_capacity) = if let Some(na) = &config.ia_na {
            let end = na.pool_end.unwrap_or(na.pool_start + 0xFFFF);
            (na.pool_start, end - na.pool_start)
        } else {
            (0, 0)
        };

        let (pd_pool_start, pd_range_capacity) =
            if let Some(_pd) = &config.ia_pd { (0u32, 256u32) } else { (0, 0) };

        let mut status = DhcpV6AssignStatus {
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            na_config: config.ia_na.clone(),
            na_pool_start,
            na_range_capacity,
            na_allocated_suffixes: HashMap::new(),
            na_offered: HashMap::new(),
            pd_config: config.ia_pd.clone(),
            pd_pool_start,
            pd_range_capacity,
            pd_allocated_indices: HashMap::new(),
            pd_offered: HashMap::new(),
            static_bindings: HashMap::new(),
            last_offer_info: DHCPv6OfferInfo::default(),
        };

        for device in devices {
            if let Some(ipv6) = device.ipv6 {
                status.static_bindings.insert(device.mac, ipv6);
            }
        }

        status
    }

    #[cfg(test)]
    pub fn init_for_test(config: DHCPv6ServerConfig) -> Self {
        Self::from_config_and_devices(&config, vec![])
    }

    pub fn offer_na_suffix(
        &mut self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
    ) -> Option<u64> {
        let na_config = match &self.na_config {
            Some(c) => c,
            None => return None,
        };
        let valid_lifetime = na_config.valid_lifetime;
        let preferred_lifetime = na_config.preferred_lifetime;

        if let Some(mac) = &mac {
            if let Some(suffix_addr) = self.static_bindings.get(mac) {
                let suffix = u128::from(*suffix_addr) as u64;
                // kick any dynamic client that currently holds this suffix
                let conflicting_duid = self
                    .na_offered
                    .iter()
                    .find(|(_, c)| c.suffix == suffix && !c.is_static)
                    .map(|(duid, _)| duid.clone());
                if let Some(ref duid) = conflicting_duid {
                    self.na_offered.remove(duid);
                    self.na_allocated_suffixes.remove(&suffix);
                }
                // also clean up if this same client previously had a dynamic offer
                if matches!(self.na_offered.get(client_duid), Some(c) if !c.is_static) {
                    if let Some(old_cache) = self.na_offered.remove(client_duid) {
                        self.na_allocated_suffixes.remove(&old_cache.suffix);
                    }
                }
                self.na_allocated_suffixes.insert(suffix, true);
                self.na_offered.insert(
                    client_duid.to_vec(),
                    DHCPv6NACache {
                        suffix,
                        hostname,
                        mac: Some(*mac),
                        duid_hex: duid_to_hex(client_duid),
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: valid_lifetime,
                        preferred_time: preferred_lifetime,
                        is_static: true,
                    },
                );
                return Some(suffix);
            }
        }

        if let Some(cache) = self.na_offered.get(client_duid) {
            return Some(cache.suffix);
        }

        if self.na_range_capacity == 0 {
            return None;
        }

        let mut seed = hash_duid(client_duid);
        loop {
            if self.na_allocated_suffixes.len() as u64 >= self.na_range_capacity {
                if !self.clean_expired_na() {
                    tracing::error!("DHCPv6 NA pool is full");
                    return None;
                }
            }
            let index = seed % self.na_range_capacity;
            let suffix = self.na_pool_start + index;
            if self.na_allocated_suffixes.contains_key(&suffix) {
                seed = seed.wrapping_add(1);
            } else {
                self.na_allocated_suffixes.insert(suffix, true);
                self.na_offered.insert(
                    client_duid.to_vec(),
                    DHCPv6NACache {
                        suffix,
                        hostname,
                        mac,
                        duid_hex: duid_to_hex(client_duid),
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        preferred_time: preferred_lifetime.min(OFFER_VALID_TIME),
                        is_static: false,
                    },
                );
                return Some(suffix);
            }
        }
    }

    pub fn confirm_na(&mut self, client_duid: &[u8]) -> bool {
        let na_config = match &self.na_config {
            Some(c) => c,
            None => return false,
        };
        if let Some(cache) = self.na_offered.get_mut(client_duid) {
            if !cache.is_static {
                cache.valid_time = na_config.valid_lifetime;
            }
            cache.preferred_time = na_config.preferred_lifetime;
            cache.relative_offer_time = self.relative_boot_time.elapsed().as_secs();
            true
        } else {
            false
        }
    }

    pub fn release_na(&mut self, client_duid: &[u8]) {
        if let Some(cache) = self.na_offered.remove(client_duid) {
            if !cache.is_static {
                self.na_allocated_suffixes.remove(&cache.suffix);
            }
        }
    }

    pub fn clean_expired_na(&mut self) -> bool {
        let current_time = self.relative_boot_time.elapsed().as_secs();
        let mut removed = vec![];
        self.na_offered.retain(|_, cache| {
            if cache.is_static {
                return true;
            }
            if current_time > cache.relative_offer_time + cache.valid_time as u64 {
                removed.push(cache.suffix);
                false
            } else {
                true
            }
        });
        for suffix in &removed {
            self.na_allocated_suffixes.remove(suffix);
        }
        !removed.is_empty()
    }

    pub fn offer_pd_index(
        &mut self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
    ) -> Option<u32> {
        let pd_preferred = self.pd_config.as_ref()?.preferred_lifetime;

        if qualifying_prefixes.is_empty() {
            return None;
        }

        if let Some(cache) = self.pd_offered.get(client_duid) {
            if (cache.sub_index as usize) < qualifying_prefixes.len() {
                return Some(cache.sub_index);
            }
            let sub_index = cache.sub_index;
            self.pd_offered.remove(client_duid);
            self.pd_allocated_indices.remove(&sub_index);
        }

        loop {
            for (idx, _) in qualifying_prefixes.iter().enumerate() {
                let idx = idx as u32;
                if !self.pd_allocated_indices.contains_key(&idx) {
                    self.pd_allocated_indices.insert(idx, true);
                    self.pd_offered.insert(
                        client_duid.to_vec(),
                        DHCPv6PDCache {
                            sub_index: idx,
                            duid_hex: duid_to_hex(client_duid),
                            relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                            valid_time: OFFER_VALID_TIME,
                            preferred_time: pd_preferred.min(OFFER_VALID_TIME),
                            client_addr: Ipv6Addr::UNSPECIFIED,
                            active_routes: Vec::new(),
                        },
                    );
                    return Some(idx);
                }
            }

            if self.clean_expired_pd().is_empty() {
                tracing::warn!("DHCPv6 PD pool exhausted ({} slots)", qualifying_prefixes.len());
                return None;
            }
        }
    }

    pub fn confirm_pd(&mut self, client_duid: &[u8]) -> bool {
        let pd_config = match &self.pd_config {
            Some(c) => c,
            None => return false,
        };
        if let Some(cache) = self.pd_offered.get_mut(client_duid) {
            cache.valid_time = pd_config.valid_lifetime;
            cache.preferred_time = pd_config.preferred_lifetime;
            cache.relative_offer_time = self.relative_boot_time.elapsed().as_secs();
            true
        } else {
            false
        }
    }

    pub fn release_pd(&mut self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        if let Some(cache) = self.pd_offered.remove(client_duid) {
            self.pd_allocated_indices.remove(&cache.sub_index);
            Some(cache)
        } else {
            None
        }
    }

    pub fn clean_expired_pd(&mut self) -> Vec<DHCPv6PDCache> {
        let current_time = self.relative_boot_time.elapsed().as_secs();
        let expired_keys: Vec<Vec<u8>> = self
            .pd_offered
            .iter()
            .filter(|(_, cache)| current_time > cache.relative_offer_time + cache.valid_time as u64)
            .map(|(k, _)| k.clone())
            .collect();

        let mut removed_caches = Vec::new();
        for key in expired_keys {
            if let Some(cache) = self.pd_offered.remove(&key) {
                self.pd_allocated_indices.remove(&cache.sub_index);
                removed_caches.push(cache);
            }
        }
        removed_caches
    }

    pub fn add_or_update_binding(&mut self, mac: MacAddr, ipv6_addr: Ipv6Addr) {
        let suffix = u128::from(ipv6_addr) as u64;

        let kicked = {
            if self.na_allocated_suffixes.contains_key(&suffix) {
                self.na_offered
                    .iter()
                    .find(|(_, cache)| cache.suffix == suffix && !cache.is_static)
                    .map(|(duid, cache)| {
                        let duid = duid.clone();
                        let hostname = cache.hostname.clone();
                        let kicked_mac = cache.mac;
                        (duid, hostname, kicked_mac)
                    })
            } else {
                None
            }
        };

        if let Some((ref duid, _, _)) = kicked {
            self.na_offered.remove(duid);
            self.na_allocated_suffixes.remove(&suffix);
        }

        self.static_bindings.insert(mac, ipv6_addr);
        self.na_allocated_suffixes.insert(suffix, true);

        if let Some((duid, hostname, kicked_mac)) = kicked {
            self.offer_na_suffix(&duid, kicked_mac, hostname);
        }
    }

    pub fn remove_binding(&mut self, mac: &MacAddr) {
        self.static_bindings.remove(mac);

        let to_remove: Vec<Vec<u8>> = self
            .na_offered
            .iter()
            .filter(|(_, cache)| cache.is_static && cache.mac == Some(*mac))
            .map(|(duid, _)| duid.clone())
            .collect();

        for duid in to_remove {
            if let Some(cache) = self.na_offered.remove(&duid) {
                self.na_allocated_suffixes.remove(&cache.suffix);
            }
        }
    }

    pub fn get_offered_info(
        &self,
        na_prefixes: &[(Ipv6Addr, u8)],
        pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> DHCPv6OfferInfo {
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();

        let mut offered_addresses = Vec::new();
        for (_, cache) in &self.na_offered {
            for (prefix, prefix_len) in na_prefixes {
                let ip = combine_prefix_suffix(*prefix, *prefix_len, cache.suffix);
                offered_addresses.push(DHCPv6AddressItem {
                    duid: Some(cache.duid_hex.clone()),
                    mac: cache.mac,
                    ip,
                    hostname: cache.hostname.clone(),
                    relative_active_time: cache.relative_offer_time,
                    preferred_lifetime: cache.preferred_time,
                    valid_lifetime: cache.valid_time,
                    is_static: cache.is_static,
                });
            }
        }

        let mut delegated_prefixes = Vec::new();
        for (_, cache) in &self.pd_offered {
            if self.pd_config.is_some() {
                if let Some((base_prefix, base_prefix_len)) =
                    pd_prefixes.get(cache.sub_index as usize)
                {
                    let delegated = compute_delegated_prefix(
                        *base_prefix,
                        *base_prefix_len,
                        *base_prefix_len,
                        0,
                    );
                    delegated_prefixes.push(DHCPv6PrefixItem {
                        duid: Some(cache.duid_hex.clone()),
                        prefix: delegated,
                        prefix_len: *base_prefix_len,
                        relative_active_time: cache.relative_offer_time,
                        preferred_lifetime: cache.preferred_time,
                        valid_lifetime: cache.valid_time,
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
}

pub fn compute_qualifying_na_prefixes(
    na_config: &Option<DHCPv6IANAConfig>,
    runtime_sources: &[Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>],
    static_infos: &[ICMPv6ConfigInfo],
) -> Vec<(Ipv6Addr, u8)> {
    let na_config = match na_config {
        Some(c) => c,
        None => return vec![],
    };
    let mut result = vec![];

    for info in static_infos {
        if info.sub_prefix_len <= na_config.max_prefix_len {
            result.push((info.sub_prefix, info.sub_prefix_len));
        }
    }

    for source in runtime_sources {
        let loaded = source.load();
        if let Some(info) = loaded.as_ref() {
            if info.sub_prefix_len <= na_config.max_prefix_len {
                result.push((info.sub_prefix, info.sub_prefix_len));
            }
        }
    }

    result
}

pub fn compute_qualifying_pd_prefixes(
    pd_config: &Option<DHCPv6IAPDConfig>,
    pd_delegation_static: &[PdDelegationParent],
    pd_delegation_dynamic: &[Arc<ArcSwap<Option<PdDelegationParent>>>],
) -> Vec<(Ipv6Addr, u8)> {
    let pd_config = match pd_config {
        Some(c) => c,
        None => return vec![],
    };
    let dl = pd_config.delegate_prefix_len;
    let mut result = vec![];

    for p in pd_delegation_static {
        if p.prefix_len <= dl {
            result.push((p.prefix, p.prefix_len));
        }
    }

    for src in pd_delegation_dynamic {
        if let Some(p) = src.load().as_ref() {
            if p.prefix_len <= dl {
                result.push((p.prefix, p.prefix_len));
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use landscape_common::dhcp::v6_server::config::{
        DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
    };
    use landscape_common::enrolled_device::EnrolledDevice;
    use landscape_common::net::MacAddr;

    use super::*;

    fn na_config() -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        }
    }

    fn na_pd_config() -> DHCPv6ServerConfig {
        DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 256,
                pool_end: Some(512),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: Some(DHCPv6IAPDConfig {
                delegate_prefix_len: 61,
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
        }
    }

    #[test]
    fn t1_init_with_naconfig() {
        let status = DhcpV6AssignStatus::init_for_test(na_config());
        assert!(status.na_config.is_some());
        assert!(status.pd_config.is_none());
        assert_eq!(status.na_config.as_ref().unwrap().max_prefix_len, 64);
        assert_eq!(status.na_pool_start, 256);
        assert!(status.na_range_capacity > 0);
    }

    #[test]
    fn t2_offer_na_dynamic() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let duid = b"client-1".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let suffix = status.offer_na_suffix(&duid, Some(mac), None);
        assert!(suffix.is_some());
        assert!(status.na_offered.contains_key(&duid));
        assert!(!status.na_offered.get(&duid).unwrap().is_static);
    }

    #[test]
    fn t3_offer_na_static() {
        let config = na_config();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let static_ip = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0x100);

        let device = EnrolledDevice {
            mac,
            name: "test".to_string(),
            ipv4: None,
            ipv6: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:11:22:33:44:55",
                "name": "test"
            }))
            .unwrap()
        };

        let mut status = DhcpV6AssignStatus::from_config_and_devices(&config, vec![device]);
        let duid = b"client-static".to_vec();
        let suffix = status.offer_na_suffix(&duid, Some(mac), None);
        assert!(suffix.is_some());
        assert!(status.na_offered.get(&duid).unwrap().is_static);
        assert_eq!(suffix.unwrap(), 0x100);
    }

    #[test]
    fn t4_confirm_na() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let duid = b"client-confirm".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        status.offer_na_suffix(&duid, Some(mac), None);
        assert!(status.confirm_na(&duid));

        let cache = status.na_offered.get(&duid).unwrap();
        assert_eq!(cache.valid_time, 7200);
    }

    #[test]
    fn t5_release_na() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let duid = b"client-release".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let suffix = status.offer_na_suffix(&duid, Some(mac), None).unwrap();
        assert!(status.na_allocated_suffixes.contains_key(&suffix));

        status.release_na(&duid);
        assert!(!status.na_offered.contains_key(&duid));
        assert!(!status.na_allocated_suffixes.contains_key(&suffix));
    }

    #[test]
    fn t6_release_na_preserves_static() {
        let config = na_config();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let static_ip = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0x200);

        let device = EnrolledDevice {
            mac,
            name: "test".to_string(),
            ipv4: None,
            ipv6: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:11:22:33:44:55",
                "name": "test"
            }))
            .unwrap()
        };

        let mut status = DhcpV6AssignStatus::from_config_and_devices(&config, vec![device]);
        let duid = b"static-release".to_vec();
        let suffix = status.offer_na_suffix(&duid, Some(mac), None).unwrap();

        status.release_na(&duid);
        assert!(!status.na_offered.contains_key(&duid));
        assert!(status.na_allocated_suffixes.contains_key(&suffix));
    }

    #[test]
    fn t7_clean_expired_na_preserves_static() {
        let config = na_config();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let static_ip = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0x300);

        let device = EnrolledDevice {
            mac,
            name: "test".to_string(),
            ipv4: None,
            ipv6: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:11:22:33:44:55",
                "name": "test"
            }))
            .unwrap()
        };

        let mut status = DhcpV6AssignStatus::from_config_and_devices(&config, vec![device]);
        let duid = b"static-clean".to_vec();
        status.offer_na_suffix(&duid, Some(mac), None);

        let dyn_duid = b"dynamic-clean".to_vec();
        let dyn_mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let dyn_suffix = status.offer_na_suffix(&dyn_duid, Some(dyn_mac), None).unwrap();

        status.clean_expired_na();

        assert!(status.na_offered.contains_key(&duid));
        assert!(status.na_offered.contains_key(&dyn_duid));
        assert!(status.na_allocated_suffixes.contains_key(&dyn_suffix));
    }

    #[test]
    fn t8_offer_pd_index() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let duid = b"pd-client".to_vec();
        let qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];

        let idx = status.offer_pd_index(&duid, &qualifying);
        assert!(idx.is_some());
        assert_eq!(idx.unwrap(), 0);
        assert!(status.pd_offered.contains_key(&duid));
    }

    #[test]
    fn t9_confirm_pd() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let duid = b"pd-confirm".to_vec();
        let qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];

        status.offer_pd_index(&duid, &qualifying);
        assert!(status.confirm_pd(&duid));
        let cache = status.pd_offered.get(&duid).unwrap();
        assert_eq!(cache.valid_time, 7200);
    }

    #[test]
    fn t10_release_pd() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let duid = b"pd-release".to_vec();
        let qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];

        let idx = status.offer_pd_index(&duid, &qualifying).unwrap();
        let released = status.release_pd(&duid);
        assert!(released.is_some());
        assert_eq!(released.unwrap().sub_index, idx);
        assert!(!status.pd_offered.contains_key(&duid));
        assert!(!status.pd_allocated_indices.contains_key(&idx));
    }

    #[test]
    fn t11_pd_pool_exhausted() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let qualifying = [
            (Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 0), 60),
            (Ipv6Addr::new(0xfd99, 0, 0, 1, 0, 0, 0, 0), 60),
        ];

        let r1 = status.offer_pd_index(b"a", &qualifying);
        let r2 = status.offer_pd_index(b"b", &qualifying);
        assert!(r1.is_some());
        assert!(r2.is_some());
        assert_ne!(r1.unwrap(), r2.unwrap());

        let r3 = status.offer_pd_index(b"c", &qualifying);
        assert!(r3.is_none());
    }

    #[test]
    fn t12_add_static_binding_kicks_dynamic() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let dyn_mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        let dyn_duid = b"dynamic-to-kick".to_vec();

        let dyn_suffix = status.offer_na_suffix(&dyn_duid, Some(dyn_mac), None).unwrap();

        let static_mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02]);
        let static_ip = Ipv6Addr::from(u128::from(dyn_suffix));

        status.add_or_update_binding(static_mac, static_ip);

        assert!(status.static_bindings.contains_key(&static_mac));
        // Dynamic client re-offered with a new suffix
        let reoffered = status.na_offered.get(&dyn_duid);
        assert!(reoffered.is_some(), "dynamic client should be re-offered");
        assert_ne!(reoffered.unwrap().suffix, dyn_suffix);
        assert!(!reoffered.unwrap().is_static);
    }

    #[test]
    fn t13_remove_static_binding() {
        let config = na_config();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let static_ip = Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0x400);

        let device = EnrolledDevice {
            mac,
            name: "test".to_string(),
            ipv4: None,
            ipv6: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({
                "mac": "00:11:22:33:44:55",
                "name": "test"
            }))
            .unwrap()
        };

        let mut status = DhcpV6AssignStatus::from_config_and_devices(&config, vec![device]);
        let duid = b"static-remove".to_vec();
        let suffix = status.offer_na_suffix(&duid, Some(mac), None).unwrap();

        status.remove_binding(&mac);

        assert!(!status.static_bindings.contains_key(&mac));
        assert!(!status.na_offered.contains_key(&duid));
        assert!(!status.na_allocated_suffixes.contains_key(&suffix));
    }

    #[test]
    fn t14_get_offered_info() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let na_duid = b"na-info".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        status.offer_na_suffix(&na_duid, Some(mac), None);

        let pd_duid = b"pd-info".to_vec();
        let pd_qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];
        status.offer_pd_index(&pd_duid, &pd_qualifying);

        let na_prefixes = [(Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0), 64)];
        let info = status.get_offered_info(&na_prefixes, &pd_qualifying);

        assert_eq!(info.offered_addresses.len(), 1);
        assert_eq!(info.delegated_prefixes.len(), 1);
        assert!(!info.offered_addresses[0].is_static);
    }

    #[test]
    fn t15_compute_qualifying_na_prefixes_filters() {
        use crate::ipv6::prefix::ICMPv6ConfigInfo;

        let config_48 = DHCPv6IANAConfig {
            max_prefix_len: 48,
            pool_start: 256,
            pool_end: None,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let mut info_64 = ICMPv6ConfigInfo {
            rt_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            rt_prefix_len: 48,
            sub_router: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            sub_prefix: Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0),
            sub_prefix_len: 64,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 600,
        };

        // 64 > 48 → filtered out
        let result = compute_qualifying_na_prefixes(&Some(config_48), &[], &[info_64.clone()]);
        assert!(result.is_empty(), "prefix_len 64 > 48 should be filtered");

        let config_64 = DHCPv6IANAConfig {
            max_prefix_len: 64,
            pool_start: 256,
            pool_end: None,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        // 64 <= 64 → included
        info_64.sub_prefix_len = 64;
        let result =
            compute_qualifying_na_prefixes(&Some(config_64.clone()), &[], &[info_64.clone()]);
        assert_eq!(result.len(), 1);

        // 56 <= 64 → included
        info_64.sub_prefix_len = 56;
        let result = compute_qualifying_na_prefixes(&Some(config_64), &[], &[info_64.clone()]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn t16_compute_qualifying_pd_prefixes_filters() {
        use crate::ipv6::prefix::PdDelegationParent;

        let config_56 = DHCPv6IAPDConfig {
            delegate_prefix_len: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let parent_48 = PdDelegationParent {
            prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x3900, 0, 0, 0, 0),
            prefix_len: 48,
        };
        let parent_60 = PdDelegationParent {
            prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x39a0, 0, 0, 0, 0),
            prefix_len: 60,
        };
        let parent_56 = PdDelegationParent {
            prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x39b0, 0, 0, 0, 0),
            prefix_len: 56,
        };

        let result = compute_qualifying_pd_prefixes(
            &Some(config_56),
            &[parent_48, parent_60, parent_56],
            &[],
        );

        assert_eq!(
            result.len(),
            2,
            "/48 and /56 qualify under delegate_prefix_len=56, /60 filtered"
        );
        assert!(result.iter().all(|(_, len)| *len <= 56));
    }

    #[test]
    fn t17_offer_na_no_config_returns_none() {
        let config = DHCPv6ServerConfig { enable: true, ia_na: None, ia_pd: None };
        let mut status = DhcpV6AssignStatus::init_for_test(config);
        let duid = b"client".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(status.offer_na_suffix(&duid, Some(mac), None).is_none());
    }

    #[test]
    fn t18_offer_na_pool_capacity_zero_returns_none() {
        let config = DHCPv6ServerConfig {
            enable: true,
            ia_na: Some(DHCPv6IANAConfig {
                max_prefix_len: 64,
                pool_start: 0,
                pool_end: Some(0),
                preferred_lifetime: 3600,
                valid_lifetime: 7200,
            }),
            ia_pd: None,
        };
        let mut status = DhcpV6AssignStatus::init_for_test(config);
        assert_eq!(status.na_range_capacity, 0);
        let duid = b"client".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(status.offer_na_suffix(&duid, Some(mac), None).is_none());
    }

    #[test]
    fn t19_confirm_na_unknown_duid_returns_false() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        assert!(!status.confirm_na(b"unknown-duid"));
    }

    #[test]
    fn t20_confirm_na_static_preserves_valid_time() {
        let config = na_config();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let static_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0xFF);
        let device = EnrolledDevice {
            mac,
            name: "t".to_string(),
            ipv4: None,
            ipv6: Some(static_ip),
            ..serde_json::from_value(serde_json::json!({"mac": "00:11:22:33:44:55", "name": "t"}))
                .unwrap()
        };
        let mut status = DhcpV6AssignStatus::from_config_and_devices(&config, vec![device]);
        let duid = b"static-confirm".to_vec();
        status.offer_na_suffix(&duid, Some(mac), None);
        let before = status.na_offered.get(&duid).unwrap().valid_time;
        status.confirm_na(&duid);
        let after = status.na_offered.get(&duid).unwrap().valid_time;
        assert_eq!(before, after);
    }

    #[test]
    fn t21_release_na_unknown_duid_no_panic() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        status.release_na(b"unknown");
    }

    #[test]
    fn t22_clean_expired_na_returns_false_when_nothing_expired() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        assert!(!status.clean_expired_na());
    }

    #[test]
    fn t23_offer_pd_no_config_returns_none() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];
        assert!(status.offer_pd_index(b"pd-client", &qualifying).is_none());
    }

    #[test]
    fn t24_offer_pd_empty_qualifying_returns_none() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let qualifying: [(Ipv6Addr, u8); 0] = [];
        assert!(status.offer_pd_index(b"pd-client", &qualifying).is_none());
    }

    #[test]
    fn t25_offer_pd_stale_index_reallocation() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());

        // Pre-fill slot 0 with another client so our test client gets index 1
        status.pd_allocated_indices.insert(0, true);
        status.pd_offered.insert(
            b"other".to_vec(),
            DHCPv6PDCache {
                sub_index: 0,
                duid_hex: "other".to_string(),
                relative_offer_time: 0,
                valid_time: 120,
                preferred_time: 120,
                client_addr: Ipv6Addr::UNSPECIFIED,
                active_routes: Vec::new(),
            },
        );

        let duid = b"stale-pd".to_vec();
        let two_prefixes = [
            (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 48),
            (Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 48),
        ];
        // Allocates index 1 (slot 0 already occupied)
        let idx = status.offer_pd_index(&duid, &two_prefixes);
        assert_eq!(idx, Some(1));

        // Shrink qualifying prefixes: sub_index 1 is now stale (1 >= 1)
        let one_prefix = [(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 48)];
        let result = status.offer_pd_index(&duid, &one_prefix);
        // Stale entry removed, but slot 0 still occupied by other client
        assert_eq!(result, None);
        assert!(!status.pd_offered.contains_key(&duid));
        assert!(!status.pd_allocated_indices.contains_key(&1));
    }

    #[test]
    fn t26_confirm_pd_unknown_duid_returns_false() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        assert!(!status.confirm_pd(b"unknown"));
    }

    #[test]
    fn t27_release_pd_unknown_duid_returns_none() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        assert!(status.release_pd(b"unknown").is_none());
    }

    #[test]
    fn t28_add_binding_no_conflict() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let new_mac = MacAddr::from([0xCA, 0xFE, 0x00, 0x00, 0x00, 0x01]);
        let new_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x999);
        status.add_or_update_binding(new_mac, new_ip);
        assert!(status.static_bindings.contains_key(&new_mac));
        assert!(status.na_allocated_suffixes.contains_key(&0x999));
    }

    #[test]
    fn t29_remove_binding_unknown_mac_no_panic() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let mac = MacAddr::from([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        status.remove_binding(&mac);
        assert!(status.static_bindings.is_empty());
    }

    #[test]
    fn t30_get_offered_info_empty_inputs() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        let duid = b"empty-info".to_vec();
        let mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        status.offer_na_suffix(&duid, Some(mac), None);

        let pd_qualifying = [(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 56)];
        status.offer_pd_index(b"pd-empty-info", &pd_qualifying);

        let empty: [(Ipv6Addr, u8); 0] = [];
        let info = status.get_offered_info(&empty, &pd_qualifying);
        assert_eq!(info.offered_addresses.len(), 0);
        assert_eq!(info.delegated_prefixes.len(), 1);

        let na_prefixes = [(Ipv6Addr::new(0xfd11, 0x2222, 0x3333, 0x4444, 0, 0, 0, 0), 64)];
        let info = status.get_offered_info(&na_prefixes, &empty);
        assert_eq!(info.offered_addresses.len(), 1);
        assert_eq!(info.delegated_prefixes.len(), 0);
    }

    #[test]
    fn t31_static_binding_kicks_existing_dynamic_offer() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let dyn_mac = MacAddr::from([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x10]);
        let dyn_duid = b"dyn-then-static".to_vec();

        // First: dynamic allocation
        let dyn_suffix = status.offer_na_suffix(&dyn_duid, Some(dyn_mac), None);
        assert!(dyn_suffix.is_some());
        assert!(!status.na_offered.get(&dyn_duid).unwrap().is_static);

        // Then: same client gets a static binding with a different address
        let static_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x5678);
        status.static_bindings.insert(dyn_mac, static_ip);

        // Call offer_na_suffix again with the same mac → should switch to static
        let result = status.offer_na_suffix(&dyn_duid, Some(dyn_mac), None);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 0x5678);
        let cache = status.na_offered.get(&dyn_duid).unwrap();
        assert!(cache.is_static);
        assert_eq!(cache.suffix, 0x5678);
        assert!(!status.na_allocated_suffixes.contains_key(&dyn_suffix.unwrap()));
    }

    #[test]
    fn t32_clean_expired_pd_returns_empty_when_nothing_expired() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_pd_config());
        assert!(status.clean_expired_pd().is_empty());
    }

    #[test]
    fn t33_na_pool_exhausted_without_expired() {
        let mut status = DhcpV6AssignStatus::init_for_test(na_config());
        let num_slots = status.na_range_capacity as usize;
        // Allocate every slot
        for i in 0..num_slots {
            let duid = format!("client-{}", i).into_bytes();
            let mac = MacAddr::from([0x00, 0x00, 0x00, 0x00, (i >> 8) as u8, i as u8]);
            let suffix = status.offer_na_suffix(&duid, Some(mac), None);
            assert!(suffix.is_some(), "slot {i} should allocate");
        }
        // Pool should be full now
        let duid = b"overflow-client".to_vec();
        let mac = MacAddr::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let result = status.offer_na_suffix(&duid, Some(mac), None);
        assert!(result.is_none(), "pool exhausted: should return None");
    }

    #[test]
    fn t34_compute_qualifying_na_prefixes_from_runtime_sources() {
        use crate::ipv6::prefix::ICMPv6ConfigInfo;
        use arc_swap::ArcSwap;
        use std::sync::Arc;

        let config = DHCPv6IANAConfig {
            max_prefix_len: 64,
            pool_start: 256,
            pool_end: None,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let info = ICMPv6ConfigInfo {
            rt_prefix: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            rt_prefix_len: 48,
            sub_router: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            sub_prefix: Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0),
            sub_prefix_len: 56,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 600,
        };
        let runtime: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
            Arc::new(ArcSwap::new(Arc::new(Some(info))));

        let result = compute_qualifying_na_prefixes(&Some(config.clone()), &[runtime], &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0), 56));

        // Runtime source with None
        let none_runtime: Arc<ArcSwap<Option<ICMPv6ConfigInfo>>> =
            Arc::new(ArcSwap::new(Arc::new(None)));
        let result = compute_qualifying_na_prefixes(&Some(config), &[none_runtime], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn t35_compute_qualifying_pd_prefixes_from_dynamic_sources() {
        use crate::ipv6::prefix::PdDelegationParent;
        use arc_swap::ArcSwap;
        use std::sync::Arc;

        let config = DHCPv6IAPDConfig {
            delegate_prefix_len: 56,
            preferred_lifetime: 3600,
            valid_lifetime: 7200,
        };

        let parent = PdDelegationParent {
            prefix: Ipv6Addr::new(0xfd99, 0, 0, 0x3900, 0, 0, 0, 0),
            prefix_len: 48,
        };
        let dyn_source: Arc<ArcSwap<Option<PdDelegationParent>>> =
            Arc::new(ArcSwap::new(Arc::new(Some(parent))));

        let result = compute_qualifying_pd_prefixes(&Some(config.clone()), &[], &[dyn_source]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], (Ipv6Addr::new(0xfd99, 0, 0, 0x3900, 0, 0, 0, 0), 48));

        // None dynamic source
        let none_src: Arc<ArcSwap<Option<PdDelegationParent>>> =
            Arc::new(ArcSwap::new(Arc::new(None)));
        let result = compute_qualifying_pd_prefixes(&Some(config), &[], &[none_src]);
        assert!(result.is_empty());
    }
}
