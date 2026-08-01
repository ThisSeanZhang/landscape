use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use super::config::{
    IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6ServiceConfigV2, PrefixGroupServiceKind,
};
use crate::service::ServiceConfigError;
use crate::wan_service::ipv6_pd::LDIAPrefix;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PrefixParentSource {
    Static {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        parent_prefix_len: u8,
    },
    Pd {
        depend_iface: String,
        #[serde(alias = "planned_parent_prefix_len")]
        expected_pd_len_snapshot: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RaPrefixConfig {
    pub pool_index: u32,
    // Deprecated: kept only for backward-compatible deserialization.
    // RA lifetimes are now derived globally from lifetime.
    // Remove both fields and their default helpers together. Configs saved without them
    // can roll back to this version through the 300/600 serde defaults below.
    #[serde(default = "default_ra_preferred_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub preferred_lifetime: u32,
    #[serde(default = "default_ra_valid_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub valid_lifetime: u32,
}

fn default_ra_preferred_lifetime() -> u32 {
    300
}

fn default_ra_valid_lifetime() -> u32 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NaPrefixConfig {
    pub pool_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PdPrefixRangeConfig {
    pub pool_len: u8,
    pub start_index: u32,
    pub end_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanPrefixGroupConfig {
    pub group_id: String,
    pub parent: PrefixParentSource,
    #[serde(default)]
    pub ra: Option<RaPrefixConfig>,
    #[serde(default)]
    pub na: Option<NaPrefixConfig>,
    #[serde(default)]
    pub pd: Option<PdPrefixRangeConfig>,
}

#[derive(Debug, Clone)]
pub struct PdPrefixContext {
    pub expected_pd_len: u8,
    pub actual_prefix: Option<LDIAPrefix>,
}

pub type PdPrefixContextMap = HashMap<String, PdPrefixContext>;

fn normalize_ipv6_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let value = u128::from_be_bytes(addr.octets());
    let masked = if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        value
    } else {
        let mask = (!0u128) << (128 - prefix_len as u32);
        value & mask
    };
    Ipv6Addr::from(masked.to_be_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpandedParentKey {
    Resolved(Ipv6Addr),
    PdFallback(String),
}

impl PrefixParentSource {
    pub fn resolved_parent_prefix_len(&self) -> u8 {
        match self {
            PrefixParentSource::Static { parent_prefix_len, .. } => *parent_prefix_len,
            PrefixParentSource::Pd { expected_pd_len_snapshot, .. } => *expected_pd_len_snapshot,
        }
    }

    pub fn expanded_parent_key(
        &self,
        pd_contexts: Option<&PdPrefixContextMap>,
    ) -> ExpandedParentKey {
        match self {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                ExpandedParentKey::Resolved(normalize_ipv6_prefix(*base_prefix, *parent_prefix_len))
            }
            PrefixParentSource::Pd { depend_iface, expected_pd_len_snapshot } => {
                if let Some(prefix) = pd_contexts
                    .and_then(|contexts| contexts.get(depend_iface))
                    .and_then(|context| context.actual_prefix.as_ref())
                {
                    let actual_network = normalize_ipv6_prefix(prefix.prefix_ip, prefix.prefix_len);
                    ExpandedParentKey::Resolved(normalize_ipv6_prefix(
                        actual_network,
                        *expected_pd_len_snapshot,
                    ))
                } else {
                    ExpandedParentKey::PdFallback(depend_iface.clone())
                }
            }
        }
    }
}

pub fn is_ula(addr: Ipv6Addr) -> bool {
    let first_byte = addr.octets()[0];
    (first_byte & 0xfe) == 0xfc
}

pub fn blocks_overlap(
    _parent_prefix_len: u8,
    idx_a: u64,
    len_a: u8,
    idx_b: u64,
    len_b: u8,
) -> bool {
    let max_len = len_a.max(len_b);
    let scale_a = 1u64 << (max_len - len_a) as u64;
    let start_a = idx_a * scale_a;
    let end_a = start_a + scale_a;
    let scale_b = 1u64 << (max_len - len_b) as u64;
    let start_b = idx_b * scale_b;
    let end_b = start_b + scale_b;
    start_a < end_b && start_b < end_a
}

#[derive(Debug, Clone)]
pub struct ExpandedPrefixEntry {
    pub parent: ExpandedParentKey,
    pub parent_prefix_len: u8,
    pub service_kind: PrefixGroupServiceKind,
    pub start_index: u32,
    pub end_index: u32,
    pub pool_len: u8,
}

impl ExpandedPrefixEntry {
    fn parents_are_comparable(&self, other: &Self) -> bool {
        match (&self.parent, &other.parent) {
            (ExpandedParentKey::Resolved(_), ExpandedParentKey::Resolved(_)) => true,
            (ExpandedParentKey::PdFallback(left), ExpandedParentKey::PdFallback(right)) => {
                left == right
            }
            _ => false,
        }
    }

    fn address_interval(&self) -> Option<(u128, u128)> {
        if self.pool_len == 0 || self.pool_len > 128 || self.pool_len < self.parent_prefix_len {
            return None;
        }

        let parent = match self.parent {
            ExpandedParentKey::Resolved(network) => u128::from(network),
            ExpandedParentKey::PdFallback(_) => 0,
        };
        let shift = 128 - self.pool_len as u32;
        let block_size = 1u128.checked_shl(shift)?;
        let start = parent.checked_add((self.start_index as u128).checked_mul(block_size)?)?;
        let last_start = parent.checked_add((self.end_index as u128).checked_mul(block_size)?)?;
        let host_mask = block_size - 1;
        Some((start, last_start | host_mask))
    }

    /// Return the occupied global /64 slots, independent of the parent prefix.
    fn global_slot_interval(&self) -> Option<(u128, u128)> {
        if self.pool_len == 0 || self.pool_len > 64 || self.start_index > self.end_index {
            return None;
        }

        let block_size = 1u128.checked_shl((64 - self.pool_len) as u32)?;
        let start = (self.start_index as u128).checked_mul(block_size)?;
        let end =
            ((self.end_index as u128).checked_add(1)?).checked_mul(block_size)?.checked_sub(1)?;
        Some((start, end))
    }
}

impl LanPrefixGroupConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        self.validate_with_pd_context(None)
    }

    pub fn validate_with_pd_context(
        &self,
        pd_contexts: Option<&PdPrefixContextMap>,
    ) -> Result<(), ServiceConfigError> {
        if self.group_id.trim().is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Prefix group id must not be empty".to_string(),
            });
        }

        match &self.parent {
            PrefixParentSource::Static { parent_prefix_len, .. } => {
                if *parent_prefix_len < 56 || *parent_prefix_len > 63 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "Static parent_prefix_len ({}) must be between 56 and 63",
                            parent_prefix_len
                        ),
                    });
                }
            }
            PrefixParentSource::Pd { depend_iface, expected_pd_len_snapshot } => {
                if depend_iface.trim().is_empty() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "PD parent interface must not be empty".to_string(),
                    });
                }
                if *expected_pd_len_snapshot == 0 || *expected_pd_len_snapshot > 127 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "PD expected_pd_len_snapshot ({}) must be between 1 and 127",
                            expected_pd_len_snapshot
                        ),
                    });
                }
                // A WAN-expectation/snapshot mismatch is an availability state, not an
                // invalid LAN configuration. Keep the configuration saveable so either
                // side can be changed later; runtime subnet activation applies that gate.
                if pd_contexts.is_some_and(|contexts| !contexts.contains_key(depend_iface)) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "PD parent interface '{}' has no IPv6 PD configuration",
                            depend_iface
                        ),
                    });
                }
            }
        }

        if let Some(pd) = &self.pd {
            if pd.pool_len == 0 || pd.pool_len > 64 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PD pool_len ({}) must be between 1 and 64", pd.pool_len),
                });
            }
            if pd.end_index < pd.start_index {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "PD range end_index ({}) must be >= start_index ({})",
                        pd.end_index, pd.start_index
                    ),
                });
            }
        }

        let parent_len = self.parent.resolved_parent_prefix_len();
        if let Some(ra) = &self.ra {
            if ra.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "RA pool_index ({}) must be >= 1 (subnet 0 is reserved for WAN)",
                        ra.pool_index
                    ),
                });
            }
            if 64 <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "RA requires parent_prefix_len ({}) to be less than 64",
                        parent_len
                    ),
                });
            }
            if !self.group_has_capacity(ra.pool_index, ra.pool_index, 64, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("RA pool_index ({}) exceeds available capacity", ra.pool_index),
                });
            }
        }
        if let Some(na) = &self.na {
            if na.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_index ({}) must be >= 1 (subnet 0 is reserved for WAN)",
                        na.pool_index
                    ),
                });
            }
            if 64 <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA requires parent_prefix_len ({}) to be less than 64",
                        parent_len
                    ),
                });
            }
            if !self.group_has_capacity(na.pool_index, na.pool_index, 64, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_index ({}) exceeds available capacity",
                        na.pool_index
                    ),
                });
            }
        }
        if let Some(pd) = &self.pd {
            if pd.start_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD start_index ({}) must be >= 1 (subnet 0 is reserved for WAN)",
                        pd.start_index
                    ),
                });
            }
            if pd.pool_len <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD pool_len ({}) must be greater than parent_prefix_len ({})",
                        pd.pool_len, parent_len
                    ),
                });
            }
            if !self.group_has_capacity(pd.start_index, pd.end_index, pd.pool_len, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD range {}-{} exceeds available capacity for pool_len /{}",
                        pd.start_index, pd.end_index, pd.pool_len
                    ),
                });
            }
        }

        Ok(())
    }

    fn group_has_capacity(
        &self,
        start_index: u32,
        end_index: u32,
        target_len: u8,
        parent_len: u8,
    ) -> bool {
        if target_len <= parent_len {
            return false;
        }
        let max_blocks = 1u64.checked_shl((target_len - parent_len) as u32).unwrap_or(u64::MAX);
        (end_index as u64) < max_blocks && start_index <= end_index
    }

    pub fn active_entries(&self, mode: IPv6ServiceMode) -> Vec<ExpandedPrefixEntry> {
        self.active_entries_with_pd_context(mode, None)
    }

    pub fn active_entries_with_pd_context(
        &self,
        mode: IPv6ServiceMode,
        pd_contexts: Option<&PdPrefixContextMap>,
    ) -> Vec<ExpandedPrefixEntry> {
        let mut result = Vec::new();
        let parent = self.parent.expanded_parent_key(pd_contexts);
        let parent_prefix_len = self.parent.resolved_parent_prefix_len();
        let include_ra = matches!(mode, IPv6ServiceMode::Slaac | IPv6ServiceMode::SlaacDhcpv6);
        let include_na = matches!(mode, IPv6ServiceMode::Stateful | IPv6ServiceMode::SlaacDhcpv6);
        let include_pd = matches!(mode, IPv6ServiceMode::Stateful | IPv6ServiceMode::SlaacDhcpv6);

        if include_ra {
            if let Some(ra) = &self.ra {
                result.push(ExpandedPrefixEntry {
                    parent: parent.clone(),
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::Ra,
                    start_index: ra.pool_index,
                    end_index: ra.pool_index,
                    pool_len: 64,
                });
            }
        }
        if include_na {
            if let Some(na) = &self.na {
                result.push(ExpandedPrefixEntry {
                    parent: parent.clone(),
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::Na,
                    start_index: na.pool_index,
                    end_index: na.pool_index,
                    pool_len: 64,
                });
            }
        }
        if include_pd {
            if let Some(pd) = &self.pd {
                result.push(ExpandedPrefixEntry {
                    parent,
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::IaPd,
                    start_index: pd.start_index,
                    end_index: pd.end_index,
                    pool_len: pd.pool_len,
                });
            }
        }
        result
    }
}

pub fn validate_prefix_groups(groups: &[LanPrefixGroupConfig]) -> Result<(), ServiceConfigError> {
    validate_prefix_groups_with_pd_context(groups, None)
}

pub fn validate_prefix_groups_with_pd_context(
    groups: &[LanPrefixGroupConfig],
    pd_contexts: Option<&PdPrefixContextMap>,
) -> Result<(), ServiceConfigError> {
    let mut group_ids = HashSet::with_capacity(groups.len());
    for group in groups {
        if !group_ids.insert(group.group_id.as_str()) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("Duplicate prefix group id: {}", group.group_id),
            });
        }
    }

    let expanded_groups: Vec<Vec<ExpandedPrefixEntry>> = groups
        .iter()
        .map(|group| {
            group.validate_with_pd_context(pd_contexts)?;

            let entries =
                group.active_entries_with_pd_context(IPv6ServiceMode::SlaacDhcpv6, pd_contexts);
            for i in 0..entries.len() {
                for j in (i + 1)..entries.len() {
                    validate_expanded_pair(&entries[i], &entries[j], true)?;
                }
            }

            Ok(entries)
        })
        .collect::<Result<_, ServiceConfigError>>()?;

    for i in 0..expanded_groups.len() {
        for j in (i + 1)..expanded_groups.len() {
            let left_entries = &expanded_groups[i];
            let right_entries = &expanded_groups[j];

            for left in left_entries {
                for right in right_entries {
                    if !left.parents_are_comparable(right) {
                        continue;
                    }
                    validate_expanded_pair(left, right, false)?;
                }
            }
        }
    }

    Ok(())
}

fn validate_expanded_pair(
    a: &ExpandedPrefixEntry,
    b: &ExpandedPrefixEntry,
    allow_ra_na_share: bool,
) -> Result<(), ServiceConfigError> {
    if allow_ra_na_share
        && matches!(
            (a.service_kind, b.service_kind),
            (PrefixGroupServiceKind::Ra, PrefixGroupServiceKind::Na)
                | (PrefixGroupServiceKind::Na, PrefixGroupServiceKind::Ra)
        )
    {
        return Ok(());
    }

    let Some((start_a, end_a)) = a.address_interval() else {
        return Ok(());
    };
    let Some((start_b, end_b)) = b.address_interval() else {
        return Ok(());
    };
    if start_a <= end_b && start_b <= end_a {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "Prefix group results conflict under the same parent prefix".to_string(),
        });
    }

    Ok(())
}

impl LanIPv6ConfigV2 {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        self.validate_with_pd_context(None)
    }

    pub fn validate_with_pd_context(
        &self,
        pd_contexts: Option<&PdPrefixContextMap>,
    ) -> Result<(), ServiceConfigError> {
        validate_prefix_groups_with_pd_context(&self.prefix_groups, pd_contexts)?;

        if self.lifetime < 60 || self.lifetime > u16::MAX as u32 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "lifetime ({}) must be between 60 and {} seconds",
                    self.lifetime,
                    u16::MAX,
                ),
            });
        }

        match self.mode {
            IPv6ServiceMode::Slaac => {
                if !self.prefix_groups.iter().any(|group| group.ra.is_some()) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Slaac mode requires at least one RA prefix group".to_string(),
                    });
                }
                if self.ra_flag.managed_address_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Slaac mode requires M flag to be 0".to_string(),
                    });
                }
                if let Some(dhcpv6) = &self.dhcpv6 {
                    if dhcpv6.enable {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: "Slaac mode does not allow DHCPv6 to be enabled".to_string(),
                        });
                    }
                }
            }
            IPv6ServiceMode::Stateful => {
                if !self.prefix_groups.iter().any(|group| group.na.is_some()) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires at least one IA_NA prefix group"
                            .to_string(),
                    });
                }
                if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires M=1 and O=1".to_string(),
                    });
                }
                let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
                    reason: "Stateful mode requires DHCPv6 configuration".to_string(),
                })?;
                if !dhcpv6.enable {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires DHCPv6 to be enabled".to_string(),
                    });
                }
                dhcpv6.validate()?;
            }
            IPv6ServiceMode::SlaacDhcpv6 => {
                let ra_groups: Vec<_> =
                    self.prefix_groups.iter().filter(|group| group.ra.is_some()).collect();
                if ra_groups.is_empty() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires at least one RA prefix group"
                            .to_string(),
                    });
                }
                for group in &ra_groups {
                    match &group.parent {
                        PrefixParentSource::Static { base_prefix, .. } => {
                            if !is_ula(*base_prefix) {
                                return Err(ServiceConfigError::InvalidConfig {
                                    reason: format!(
                                        "SlaacDhcpv6 mode requires RA prefix groups to be ULA (fc00::/7), got: {}",
                                        base_prefix
                                    ),
                                });
                            }
                        }
                        PrefixParentSource::Pd { .. } => {
                            return Err(ServiceConfigError::InvalidConfig {
                                reason: "SlaacDhcpv6 mode only allows Static RA prefix groups"
                                    .to_string(),
                            });
                        }
                    }
                }
                if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires M=1 and O=1".to_string(),
                    });
                }
                let dhcpv6_source_count = self
                    .prefix_groups
                    .iter()
                    .filter(|group| group.na.is_some() || group.pd.is_some())
                    .count();
                if dhcpv6_source_count == 0 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason:
                            "SlaacDhcpv6 mode requires at least one DHCPv6 prefix group (NA or PD)"
                                .to_string(),
                    });
                }
                let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
                    reason: "SlaacDhcpv6 mode requires DHCPv6 configuration".to_string(),
                })?;
                if !dhcpv6.enable {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires DHCPv6 to be enabled".to_string(),
                    });
                }
                dhcpv6.validate()?;
            }
        }

        Ok(())
    }

    pub fn active_entries(&self) -> Vec<ExpandedPrefixEntry> {
        self.active_entries_with_pd_context(None)
    }

    pub fn active_entries_with_pd_context(
        &self,
        pd_contexts: Option<&PdPrefixContextMap>,
    ) -> Vec<ExpandedPrefixEntry> {
        self.prefix_groups
            .iter()
            .flat_map(|group| group.active_entries_with_pd_context(self.mode, pd_contexts))
            .collect()
    }
}

pub fn validate_cross_interface_v2(
    new_config: &LanIPv6ServiceConfigV2,
    other_configs: &[LanIPv6ServiceConfigV2],
) -> Result<(), ServiceConfigError> {
    validate_cross_interface_v2_with_pd_context(new_config, other_configs, None)
}

pub fn validate_cross_interface_v2_with_pd_context(
    new_config: &LanIPv6ServiceConfigV2,
    other_configs: &[LanIPv6ServiceConfigV2],
    pd_contexts: Option<&PdPrefixContextMap>,
) -> Result<(), ServiceConfigError> {
    let new_entries = new_config.config.active_entries_with_pd_context(pd_contexts);

    for other in other_configs {
        if other.iface_name == new_config.iface_name || !other.enable {
            continue;
        }

        for left in &new_entries {
            for right in other.config.active_entries_with_pd_context(pd_contexts) {
                if !left.parents_are_comparable(&right) {
                    continue;
                }
                validate_expanded_pair(left, &right, false)?;
            }
        }
    }

    Ok(())
}

fn build_merged_configs(
    pending: &LanIPv6ServiceConfigV2,
    existing: &[LanIPv6ServiceConfigV2],
) -> Vec<LanIPv6ServiceConfigV2> {
    let mut merged: Vec<LanIPv6ServiceConfigV2> =
        existing.iter().filter(|c| c.iface_name != pending.iface_name).cloned().collect();
    merged.push(pending.clone());
    merged
}

#[derive(Debug, Clone)]
struct SourcedEntry {
    group_instance: usize,
    iface_name: String,
    group_id: String,
    entry: ExpandedPrefixEntry,
}

/// Validate all LAN IPv6 prefix configurations for global /64 slot conflicts.
///
/// This replaces the pending config for any interface with the same name, then expands
/// ALL entries from ALL configs (regardless of enable/disable or current service mode)
/// and detects any overlapping normalized /64 slots. Parent addresses are intentionally
/// ignored here: the slot index is shared by every LAN interface.
///
/// Within the same prefix group, RA + IA_NA sharing on the same subnet is still permitted.
pub fn validate_global_prefix_conflicts(
    pending: &LanIPv6ServiceConfigV2,
    existing: &[LanIPv6ServiceConfigV2],
    pd_contexts: Option<&PdPrefixContextMap>,
) -> Result<(), ServiceConfigError> {
    let merged = build_merged_configs(pending, existing);

    let mut sourced_entries: Vec<SourcedEntry> = Vec::new();
    let mut next_group_instance = 0;
    for config in &merged {
        for group in &config.config.prefix_groups {
            let group_instance = next_group_instance;
            next_group_instance += 1;
            let entries =
                group.active_entries_with_pd_context(IPv6ServiceMode::SlaacDhcpv6, pd_contexts);
            for entry in entries {
                sourced_entries.push(SourcedEntry {
                    group_instance,
                    iface_name: config.iface_name.clone(),
                    group_id: group.group_id.clone(),
                    entry,
                });
            }
        }
    }

    for i in 0..sourced_entries.len() {
        for j in (i + 1)..sourced_entries.len() {
            let left = &sourced_entries[i];
            let right = &sourced_entries[j];

            let same_group = left.group_instance == right.group_instance;
            let is_ra_na_pair = matches!(
                (left.entry.service_kind, right.entry.service_kind),
                (PrefixGroupServiceKind::Ra, PrefixGroupServiceKind::Na)
                    | (PrefixGroupServiceKind::Na, PrefixGroupServiceKind::Ra)
            );
            if same_group && is_ra_na_pair {
                continue;
            }

            let Some((start_l, end_l)) = left.entry.global_slot_interval() else {
                continue;
            };
            let Some((start_r, end_r)) = right.entry.global_slot_interval() else {
                continue;
            };
            if start_l > end_r || start_r > end_l {
                continue;
            }

            let overlap_start = start_l.max(start_r);
            let overlap_end = end_l.min(end_r);
            let slot_range = if overlap_start == overlap_end {
                format!("/64 slot {}", overlap_start)
            } else {
                format!("/64 slots {}-{}", overlap_start, overlap_end)
            };

            let desc = |s: &SourcedEntry| {
                let index_range = if s.entry.start_index == s.entry.end_index {
                    format!("{}", s.entry.start_index)
                } else {
                    format!("{}-{}", s.entry.start_index, s.entry.end_index)
                };
                format!(
                    "iface={}, group={}, {:?} index={} pool_len=/{}",
                    s.iface_name, s.group_id, s.entry.service_kind, index_range, s.entry.pool_len,
                )
            };

            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "Prefix conflict at {}: ({}) overlaps ({})",
                    slot_range,
                    desc(left),
                    desc(right),
                ),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::config::{
        ra_flag_default, LanIPv6ConfigV2, LanIPv6ServiceConfigV2, RouterFlags,
    };
    use super::super::dhcpv6_config::DHCPv6ServerConfig;
    use super::*;

    fn pd_context(
        iface_name: &str,
        expected_pd_len: u8,
        actual_prefix_len: Option<u8>,
    ) -> PdPrefixContextMap {
        HashMap::from([(
            iface_name.to_string(),
            PdPrefixContext {
                expected_pd_len,
                actual_prefix: actual_prefix_len.map(|prefix_len| LDIAPrefix {
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                    prefix_len,
                    prefix_ip: "2001:db8::".parse().unwrap(),
                    last_update_time: 0.0,
                }),
            },
        )])
    }

    #[test]
    fn test_blocks_overlap_same_index_same_len() {
        assert!(blocks_overlap(48, 0, 64, 0, 64));
    }

    #[test]
    fn test_blocks_overlap_adjacent() {
        assert!(!blocks_overlap(48, 0, 64, 1, 64));
    }

    #[test]
    fn test_blocks_overlap_nested() {
        assert!(blocks_overlap(48, 0, 62, 2, 64));
    }

    #[test]
    fn test_blocks_no_overlap_different_sizes() {
        assert!(!blocks_overlap(48, 0, 62, 4, 64));
    }

    #[test]
    fn static_parent_rejects_wan_reserved_indices() {
        let base_group = LanPrefixGroupConfig {
            group_id: "static-reserved".to_string(),
            parent: PrefixParentSource::Static {
                base_prefix: "fd00::".parse().unwrap(),
                parent_prefix_len: 56,
            },
            ra: None,
            na: None,
            pd: None,
        };

        let mut ra_group = base_group.clone();
        ra_group.ra = Some(RaPrefixConfig {
            pool_index: 0,
            preferred_lifetime: 300,
            valid_lifetime: 600,
        });
        assert!(ra_group.validate().unwrap_err().to_string().contains("reserved for WAN"));

        let mut na_group = base_group.clone();
        na_group.na = Some(NaPrefixConfig { pool_index: 0 });
        assert!(na_group.validate().unwrap_err().to_string().contains("reserved for WAN"));

        let mut pd_group = base_group;
        pd_group.pd = Some(PdPrefixRangeConfig { pool_len: 64, start_index: 0, end_index: 1 });
        assert!(pd_group.validate().unwrap_err().to_string().contains("reserved for WAN"));
    }

    #[test]
    fn static_parent_accepts_indices_after_wan_reserved_subnet() {
        let group = LanPrefixGroupConfig {
            group_id: "static-available".to_string(),
            parent: PrefixParentSource::Static {
                base_prefix: "fd00::".parse().unwrap(),
                parent_prefix_len: 56,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: Some(NaPrefixConfig { pool_index: 1 }),
            pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 2, end_index: 3 }),
        };

        assert!(validate_prefix_groups(&[group]).is_ok());
    }

    #[test]
    fn v2_stateful_requires_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Stateful,
            ad_interval: 300,
            lifetime: 300,
            ra_flag: ra_flag_default(),
            prefix_groups: vec![LanPrefixGroupConfig {
                group_id: "stateful-na".to_string(),
                parent: PrefixParentSource::Static {
                    base_prefix: "fd00::".parse().unwrap(),
                    parent_prefix_len: 60,
                },
                ra: None,
                na: Some(NaPrefixConfig { pool_index: 0 }),
                pd: None,
            }],
            dhcpv6: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn pd_pool_len_above_64_is_rejected() {
        let group = LanPrefixGroupConfig {
            group_id: "pd-too-specific".to_string(),
            parent: PrefixParentSource::Static {
                base_prefix: "fd00::".parse().unwrap(),
                parent_prefix_len: 56,
            },
            ra: None,
            na: None,
            pd: Some(PdPrefixRangeConfig { pool_len: 65, start_index: 0, end_index: 0 }),
        };

        let error = group.validate().unwrap_err().to_string();
        assert!(error.contains("between 1 and 64"), "unexpected validation error: {error}");
    }

    #[test]
    fn duplicate_group_ids_are_rejected() {
        let group = LanPrefixGroupConfig {
            group_id: "duplicate".to_string(),
            parent: PrefixParentSource::Static {
                base_prefix: "fd00::".parse().unwrap(),
                parent_prefix_len: 56,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: None,
            pd: None,
        };

        let error = validate_prefix_groups(&[group.clone(), group]).unwrap_err().to_string();
        assert!(error.contains("Duplicate prefix group id: duplicate"));
    }

    #[test]
    fn v2_slaac_does_not_allow_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Slaac,
            ad_interval: 300,
            lifetime: 300,
            ra_flag: RouterFlags {
                managed_address_config: false,
                other_config: false,
                ..ra_flag_default()
            },
            prefix_groups: vec![LanPrefixGroupConfig {
                group_id: "slaac-ra".to_string(),
                parent: PrefixParentSource::Static {
                    base_prefix: "fd00::".parse().unwrap(),
                    parent_prefix_len: 60,
                },
                ra: Some(RaPrefixConfig {
                    pool_index: 0,
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                na: None,
                pd: None,
            }],
            dhcpv6: Some(DHCPv6ServerConfig { enable: true, ..DHCPv6ServerConfig::default() }),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_slaac_dhcpv6_rejects_pd_ra_groups() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::SlaacDhcpv6,
            ad_interval: 300,
            lifetime: 300,
            ra_flag: ra_flag_default(),
            prefix_groups: vec![
                LanPrefixGroupConfig {
                    group_id: "ra-pd".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "eth0".to_string(),
                        expected_pd_len_snapshot: 60,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 1,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                },
                LanPrefixGroupConfig {
                    group_id: "na-static".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 60,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 1 }),
                    pd: None,
                },
            ],
            dhcpv6: Some(DHCPv6ServerConfig {
                enable: true,
                ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                    max_prefix_len: 64,
                    pool_start: 0x100,
                    pool_end: Some(0x200),
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                ia_pd: None,
            }),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_same_group_rejects_ra_pd_overlap() {
        let config = LanPrefixGroupConfig {
            group_id: "same-parent".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                expected_pd_len_snapshot: 60,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: None,
            pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 1, end_index: 1 }),
        };

        assert!(validate_prefix_groups(&[config]).is_err());
    }

    #[test]
    fn v2_same_group_allows_ra_na_share() {
        let config = LanPrefixGroupConfig {
            group_id: "same-parent".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                expected_pd_len_snapshot: 60,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: Some(NaPrefixConfig { pool_index: 1 }),
            pd: None,
        };

        assert!(validate_prefix_groups(&[config]).is_ok());
    }

    #[test]
    fn v2_pd_parent_capacity_uses_snapshot_without_runtime_prefix() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-ok".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                expected_pd_len_snapshot: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 15 }),
            pd: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn v2_pd_parent_capacity_rejects_indices_beyond_snapshot_without_runtime_prefix() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-bad".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                expected_pd_len_snapshot: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 16 }),
            pd: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_pd_parent_capacity_does_not_expand_to_runtime_prefix_len() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-runtime".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                expected_pd_len_snapshot: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 38 }),
            pd: None,
        };

        let contexts = pd_context("eth0", 60, Some(56));
        assert!(config.validate_with_pd_context(Some(&contexts)).is_err());
    }

    #[test]
    fn v2_same_runtime_pd_parent_conflicts_even_if_planned_lengths_differ() {
        let groups = vec![
            LanPrefixGroupConfig {
                group_id: "group-a".to_string(),
                parent: PrefixParentSource::Pd {
                    depend_iface: "eth0".to_string(),
                    expected_pd_len_snapshot: 60,
                },
                ra: Some(RaPrefixConfig {
                    pool_index: 1,
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                na: None,
                pd: None,
            },
            LanPrefixGroupConfig {
                group_id: "group-b".to_string(),
                parent: PrefixParentSource::Pd {
                    depend_iface: "eth0".to_string(),
                    expected_pd_len_snapshot: 56,
                },
                ra: None,
                na: None,
                pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 1, end_index: 1 }),
            },
        ];

        assert!(validate_prefix_groups(&groups).is_err());

        let contexts = pd_context("eth0", 60, Some(56));
        assert!(validate_prefix_groups_with_pd_context(&groups, Some(&contexts)).is_err());
    }

    #[test]
    fn v2_cross_interface_conflicts_when_runtime_pd_prefix_matches_across_ifaces() {
        let new_config = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-a".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan0".to_string(),
                        expected_pd_len_snapshot: 60,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let other_configs = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-b".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan1".to_string(),
                        expected_pd_len_snapshot: 56,
                    },
                    ra: None,
                    na: None,
                    pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 0, end_index: 0 }),
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }];

        let prefix = LDIAPrefix {
            preferred_lifetime: 300,
            valid_lifetime: 600,
            prefix_len: 56,
            prefix_ip: "2001:db8::".parse().unwrap(),
            last_update_time: 0.0,
        };
        let contexts = HashMap::from([
            (
                "wan0".to_string(),
                PdPrefixContext {
                    expected_pd_len: 60,
                    actual_prefix: Some(prefix.clone()),
                },
            ),
            (
                "wan1".to_string(),
                PdPrefixContext { expected_pd_len: 56, actual_prefix: Some(prefix) },
            ),
        ]);

        assert!(validate_cross_interface_v2_with_pd_context(
            &new_config,
            &other_configs,
            Some(&contexts),
        )
        .is_err());
    }

    #[test]
    fn legacy_planned_parent_prefix_len_deserializes_as_snapshot() {
        let parent: PrefixParentSource = serde_json::from_value(serde_json::json!({
            "t": "pd",
            "depend_iface": "wan0",
            "planned_parent_prefix_len": 60,
        }))
        .unwrap();

        assert_eq!(
            parent,
            PrefixParentSource::Pd {
                depend_iface: "wan0".to_string(),
                expected_pd_len_snapshot: 60,
            }
        );
        let serialized = serde_json::to_value(parent).unwrap();
        assert_eq!(serialized["expected_pd_len_snapshot"], 60);
        assert!(serialized.get("planned_parent_prefix_len").is_none());
    }

    #[test]
    fn v2_cross_interface_ra_and_na_cannot_share_same_prefix() {
        let new_config = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-a".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let other_configs = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-b".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 0 }),
                    pd: None,
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }];

        assert!(validate_cross_interface_v2(&new_config, &other_configs).is_err());
    }

    // ── Global /64 slot conflict validation tests ──

    fn config_slaac_ra(
        iface_name: &str,
        base_prefix: &str,
        parent_len: u8,
        pool_index: u32,
    ) -> LanIPv6ServiceConfigV2 {
        LanIPv6ServiceConfigV2 {
            iface_name: iface_name.to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "ra-group".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: base_prefix.parse().unwrap(),
                        parent_prefix_len: parent_len,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        }
    }

    fn config_pd_range(
        iface_name: &str,
        depend_iface: &str,
        snapshot_len: u8,
        pool_len: u8,
        start: u32,
        end: u32,
    ) -> LanIPv6ServiceConfigV2 {
        LanIPv6ServiceConfigV2 {
            iface_name: iface_name.to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "pd-group".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: depend_iface.to_string(),
                        expected_pd_len_snapshot: snapshot_len,
                    },
                    ra: None,
                    na: None,
                    pd: Some(PdPrefixRangeConfig { pool_len, start_index: start, end_index: end }),
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }
    }

    fn make_pd_context(iface_name: &str, expected_len: u8, actual_len: u8) -> PdPrefixContextMap {
        HashMap::from([(
            iface_name.to_string(),
            PdPrefixContext {
                expected_pd_len: expected_len,
                actual_prefix: Some(LDIAPrefix {
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                    prefix_len: actual_len,
                    prefix_ip: "2001:db8::".parse().unwrap(),
                    last_update_time: 0.0,
                }),
            },
        )])
    }

    #[test]
    fn global_same_group_ra_na_share_allowed() {
        let config = LanIPv6ServiceConfigV2 {
            iface_name: "lan0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::SlaacDhcpv6,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "shared".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 1,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: Some(NaPrefixConfig { pool_index: 1 }),
                    pd: None,
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        };

        assert!(validate_global_prefix_conflicts(&config, &[], None).is_ok());
    }

    #[test]
    fn global_same_parent_same_slot_conflicts() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 0);
        let existing = vec![config_slaac_ra("lan-b", "fd00::", 56, 0)];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_different_parent_prefix_len_same_64_slot_conflicts() {
        let pending = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "ra-group".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "2001:db8::".parse().unwrap(),
                        parent_prefix_len: 48,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let existing = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "ra-group2".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "2001:db8::".parse().unwrap(),
                        parent_prefix_len: 64,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        }];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_different_parents_no_conflict() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 0);
        let existing = vec![config_slaac_ra("lan-b", "fd00:0:0:1::", 56, 1)];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_ok());
    }

    #[test]
    fn global_different_parent_addresses_same_slot_conflict() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 0);
        let existing = vec![config_slaac_ra("lan-b", "2001:db8::", 56, 0)];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_pd_range_at_60_overlaps_ra_at_64_same_parent_prefix() {
        let pending = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "ra-group".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 48,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 1,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let existing = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "pd-group".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: None,
                    na: None,
                    pd: Some(PdPrefixRangeConfig { pool_len: 60, start_index: 0, end_index: 1 }),
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }];

        let result = validate_global_prefix_conflicts(&pending, &existing, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("/64 slot"), "Error should mention /64 slot: {}", err);
        assert!(err.contains("lan-a"), "Error should mention lan-a: {}", err);
        assert!(err.contains("lan-b"), "Error should mention lan-b: {}", err);
    }

    #[test]
    fn global_disabled_interface_still_checked() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 0);
        let existing = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: false,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "ra-disabled".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        }];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_merge_replaces_same_iface_old_config() {
        let existing = vec![
            config_slaac_ra("lan-a", "fd00::", 48, 2),
            config_slaac_ra("lan-b", "fd00::", 48, 1),
        ];

        let pending = config_slaac_ra("lan-a", "fd00::", 48, 0);

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_ok());
    }

    #[test]
    fn global_merge_keeps_conflict_when_replaced_iface_conflicts() {
        let existing = vec![
            config_slaac_ra("lan-a", "fd00::", 48, 1),
            config_slaac_ra("lan-b", "fd00::", 48, 0),
        ];
        let pending = config_slaac_ra("lan-a", "fd00::", 48, 0);

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_pd_runtime_context_uses_resolved_prefixes() {
        let pending = config_pd_range("lan-a", "wan0", 60, 64, 0, 0);
        let existing = config_pd_range("lan-b", "wan0", 60, 64, 0, 0);
        let contexts = make_pd_context("wan0", 60, 56);

        assert!(validate_global_prefix_conflicts(&pending, &[existing.clone()], Some(&contexts))
            .is_err());
    }

    #[test]
    fn global_unresolved_pd_parents_still_conflict_by_slot() {
        let pending = config_pd_range("lan-a", "wan-a", 60, 64, 0, 0);
        let existing = config_pd_range("lan-b", "wan-b", 60, 64, 0, 0);

        assert!(validate_global_prefix_conflicts(&pending, &[existing], None).is_err());
    }

    #[test]
    fn global_pd_range_covers_every_expanded_slot() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 20);
        let existing = vec![config_pd_range("lan-b", "wan0", 56, 60, 0, 1)];

        assert!(validate_global_prefix_conflicts(&pending, &existing, None).is_err());
    }

    #[test]
    fn global_same_group_ra_na_share_only_on_same_interface() {
        let pending = config_slaac_ra("lan-a", "fd00::", 56, 0);
        let mut existing = config_slaac_ra("lan-b", "2001:db8::", 56, 0);
        let group = &mut existing.config.prefix_groups[0];
        group.group_id = "ra-group".to_string();
        group.ra = None;
        group.na = Some(NaPrefixConfig { pool_index: 0 });

        assert!(validate_global_prefix_conflicts(&pending, &[existing], None).is_err());
    }

    #[test]
    fn global_ra_na_different_groups_same_slot_conflicts() {
        let config = LanIPv6ServiceConfigV2 {
            iface_name: "lan0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::SlaacDhcpv6,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![
                    LanPrefixGroupConfig {
                        group_id: "ra-only".to_string(),
                        parent: PrefixParentSource::Static {
                            base_prefix: "fd00::".parse().unwrap(),
                            parent_prefix_len: 56,
                        },
                        ra: Some(RaPrefixConfig {
                            pool_index: 1,
                            preferred_lifetime: 300,
                            valid_lifetime: 600,
                        }),
                        na: None,
                        pd: None,
                    },
                    LanPrefixGroupConfig {
                        group_id: "na-only".to_string(),
                        parent: PrefixParentSource::Static {
                            base_prefix: "fd00::".parse().unwrap(),
                            parent_prefix_len: 56,
                        },
                        ra: None,
                        na: Some(NaPrefixConfig { pool_index: 1 }),
                        pd: None,
                    },
                ],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        };

        assert!(validate_global_prefix_conflicts(&config, &[], None).is_err());
    }

    #[test]
    fn global_duplicate_group_ids_do_not_enable_ra_na_sharing() {
        let config = LanIPv6ServiceConfigV2 {
            iface_name: "lan0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::SlaacDhcpv6,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![
                    LanPrefixGroupConfig {
                        group_id: "duplicate".to_string(),
                        parent: PrefixParentSource::Static {
                            base_prefix: "fd00::".parse().unwrap(),
                            parent_prefix_len: 56,
                        },
                        ra: Some(RaPrefixConfig {
                            pool_index: 1,
                            preferred_lifetime: 300,
                            valid_lifetime: 600,
                        }),
                        na: None,
                        pd: None,
                    },
                    LanPrefixGroupConfig {
                        group_id: "duplicate".to_string(),
                        parent: PrefixParentSource::Static {
                            base_prefix: "2001:db8::".parse().unwrap(),
                            parent_prefix_len: 56,
                        },
                        ra: None,
                        na: Some(NaPrefixConfig { pool_index: 1 }),
                        pd: None,
                    },
                ],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(super::super::dhcpv6_config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        };

        assert!(validate_global_prefix_conflicts(&config, &[], None).is_err());
    }

    #[test]
    fn global_error_message_includes_slot_range_and_sources() {
        let pending = config_slaac_ra("lan-alpha", "fc00::", 7, 0);
        let existing = vec![config_slaac_ra("lan-beta", "fc00::", 7, 0)];

        let result = validate_global_prefix_conflicts(&pending, &existing, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();

        assert!(err.contains("/64 slot"), "Error should mention /64 slot, got: {}", err);
        assert!(err.contains("lan-alpha"), "Error should contain pending iface, got: {}", err);
        assert!(err.contains("lan-beta"), "Error should contain existing iface, got: {}", err);
        assert!(err.contains("Ra"), "Error should mention service kind, got: {}", err);
    }
}
