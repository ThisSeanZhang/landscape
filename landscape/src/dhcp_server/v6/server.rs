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
use landscape_common::net::MacAddr;
use landscape_common::utils::time::get_f64_timestamp;

use crate::ipv6::prefix::{ICMPv6ConfigInfo, PdDelegationParent};

use super::types::{DHCPv6NACache, DHCPv6PDCache};
use super::utils::{combine_prefix_suffix, compute_delegated_prefix, duid_to_hex, hash_duid};

const OFFER_VALID_TIME: u32 = 120;

pub struct DHCPv6Server {
    pub boot_time: f64,
    pub relative_boot_time: Instant,
    pub server_duid: Vec<u8>,

    // IA_NA state
    pub na_config: Option<DHCPv6IANAConfig>,
    pub na_pool_start: u64,
    pub na_range_capacity: u64,
    pub na_allocated_suffixes: HashMap<u64, bool>,
    pub na_offered: HashMap<Vec<u8>, DHCPv6NACache>, // DUID → cache

    // IA_PD state
    pub pd_config: Option<DHCPv6IAPDConfig>,
    pub pd_pool_start: u32,
    pub pd_range_capacity: u32,
    pub pd_allocated_indices: HashMap<u32, bool>,
    pub pd_offered: HashMap<Vec<u8>, DHCPv6PDCache>, // DUID → cache

    // Static bindings (MAC → suffix)
    pub static_bindings: HashMap<MacAddr, Ipv6Addr>,
}

impl DHCPv6Server {
    pub fn init(config: &DHCPv6ServerConfig, static_bindings: HashMap<MacAddr, Ipv6Addr>) -> Self {
        let (na_pool_start, na_range_capacity) = if let Some(na) = &config.ia_na {
            let end = na.pool_end.unwrap_or(na.pool_start + 0xFFFF);
            (na.pool_start, end - na.pool_start)
        } else {
            (0, 0)
        };

        // IA_PD: pool management is now handled per-source in LanIPv6SourceConfig (PdStatic/PdPd).
        // The DHCPv6 server doesn't manage the pool range itself anymore — it delegates
        // based on runtime-resolved prefixes. We keep a simple counter for sub-index allocation.
        let (pd_pool_start, pd_range_capacity) = if let Some(_pd) = &config.ia_pd {
            // Default pool: start at 0, capacity based on delegate_prefix_len
            // The actual capacity depends on the runtime source prefix, so we use a generous default
            (0u32, 256u32) // Will be bounded at runtime by available prefix space
        } else {
            (0, 0)
        };

        DHCPv6Server {
            boot_time: get_f64_timestamp(),
            relative_boot_time: Instant::now(),
            server_duid: Vec::new(), // set later
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
            static_bindings,
        }
    }

    /// Allocate or retrieve a suffix for IA_NA
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

        // Already have an offer for this DUID
        if let Some(cache) = self.na_offered.get(client_duid) {
            return Some(cache.suffix);
        }

        // Check static binding by MAC
        if let Some(mac) = &mac {
            if let Some(suffix_addr) = self.static_bindings.get(mac) {
                // DHCPv6 IA_NA uses only the low 64 bits from a static IPv6 binding.
                // The runtime address is rebuilt from the current prefix plus this suffix.
                let suffix = u128::from(*suffix_addr) as u64;
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

        if self.na_range_capacity == 0 {
            return None;
        }

        // Hash-based allocation
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

    /// Confirm NA assignment (REQUEST/RENEW/REBIND)
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

    /// Allocate one delegation block from the qualifying-prefix pool for IA_PD.
    /// `qualifying_prefixes` is the result of `get_qualifying_pd_prefixes`.
    /// Returns the pool index (0-based into `qualifying_prefixes`), stored in `DHCPv6PDCache.sub_index`.
    /// Returns `None` when the pool is exhausted and no expired leases can be reclaimed.
    pub fn offer_pd_index(
        &mut self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
    ) -> Option<u32> {
        let _pd_config = self.pd_config.as_ref()?;

        if qualifying_prefixes.is_empty() {
            return None;
        }

        if let Some(cache) = self.pd_offered.get(client_duid) {
            return Some(cache.sub_index);
        }

        // Find first free pool index
        for (idx, _) in qualifying_prefixes.iter().enumerate() {
            let idx = idx as u32;
            if !self.pd_allocated_indices.contains_key(&idx) {
                let pd_config = self.pd_config.as_ref().unwrap();
                self.pd_allocated_indices.insert(idx, true);
                self.pd_offered.insert(
                    client_duid.to_vec(),
                    DHCPv6PDCache {
                        sub_index: idx,
                        duid_hex: duid_to_hex(client_duid),
                        relative_offer_time: self.relative_boot_time.elapsed().as_secs(),
                        valid_time: OFFER_VALID_TIME,
                        preferred_time: pd_config.preferred_lifetime.min(OFFER_VALID_TIME),
                        client_addr: Ipv6Addr::UNSPECIFIED,
                        active_routes: Vec::new(),
                    },
                );
                return Some(idx);
            }
        }

        // Pool full — try cleaning expired leases
        if !self.clean_expired_pd().is_empty() {
            return self.offer_pd_index(client_duid, qualifying_prefixes);
        }

        tracing::warn!("DHCPv6 PD pool exhausted ({} slots)", qualifying_prefixes.len());
        None
    }

    /// Confirm PD assignment
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

    /// Release NA for a client
    pub fn release_na(&mut self, client_duid: &[u8]) {
        if let Some(cache) = self.na_offered.remove(client_duid) {
            if !cache.is_static {
                self.na_allocated_suffixes.remove(&cache.suffix);
            }
        }
    }

    /// Release PD for a client. Returns the removed cache for route cleanup.
    pub fn release_pd(&mut self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        if let Some(cache) = self.pd_offered.remove(client_duid) {
            self.pd_allocated_indices.remove(&cache.sub_index);
            Some(cache)
        } else {
            None
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

    /// Clean expired PD entries. Returns removed caches for route cleanup.
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

    /// Get qualifying prefixes for IA_NA from runtime sources
    pub fn get_qualifying_na_prefixes(
        &self,
        runtime_sources: &[Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>],
        static_infos: &[ICMPv6ConfigInfo],
    ) -> Vec<(Ipv6Addr, u8)> {
        let Some(na_config) = &self.na_config else {
            return vec![];
        };
        let mut result = vec![];

        // Check static sources
        for info in static_infos {
            if info.sub_prefix_len <= na_config.max_prefix_len {
                result.push((info.sub_prefix, info.sub_prefix_len));
            }
        }

        // Check PD sources
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

    /// Get qualifying base prefixes for IA_PD from dedicated PD delegation sources.
    /// Uses independent PdDelegationParent data (not NA prefix info).
    /// Filters out pool blocks whose network is smaller than the configured minimum
    /// (a /60 block cannot satisfy a /56 minimum).
    pub fn get_qualifying_pd_prefixes(
        &self,
        pd_delegation_static: &[PdDelegationParent],
        pd_delegation_dynamic: &[Arc<ArcSwap<Option<PdDelegationParent>>>],
    ) -> Vec<(Ipv6Addr, u8)> {
        let Some(pd_config) = &self.pd_config else {
            return vec![];
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

    pub fn get_offered_info(
        &self,
        runtime_sources: &[Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>],
        static_infos: &[ICMPv6ConfigInfo],
        pd_delegation_static: &[PdDelegationParent],
        pd_delegation_dynamic: &[Arc<ArcSwap<Option<PdDelegationParent>>>],
    ) -> DHCPv6OfferInfo {
        let relative_boot_time = self.relative_boot_time.elapsed().as_secs();
        let na_prefixes = self.get_qualifying_na_prefixes(runtime_sources, static_infos);

        let mut offered_addresses = Vec::new();
        for (_, cache) in &self.na_offered {
            // Show the first qualifying prefix combination
            if let Some((prefix, prefix_len)) = na_prefixes.first() {
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

        let pd_prefixes =
            self.get_qualifying_pd_prefixes(pd_delegation_static, pd_delegation_dynamic);
        let mut delegated_prefixes = Vec::new();
        for (_, cache) in &self.pd_offered {
            if let Some(_) = &self.pd_config {
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
