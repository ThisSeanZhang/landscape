use std::collections::HashMap;
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
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
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
                if *parent_prefix_len == 0 || *parent_prefix_len > 127 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "Static parent_prefix_len ({}) must be between 1 and 127",
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
            if pd.pool_len == 0 || pd.pool_len > 128 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PD pool_len ({}) must be between 1 and 128", pd.pool_len),
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
        let is_pd_parent = matches!(self.parent, PrefixParentSource::Pd { .. });
        if let Some(ra) = &self.ra {
            if is_pd_parent && ra.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "RA pool_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
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
            if is_pd_parent && na.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
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
            if is_pd_parent && pd.start_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD start_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
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
    fn v2_stateful_requires_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Stateful,
            ad_interval: 300,
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
    fn v2_slaac_does_not_allow_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Slaac,
            ad_interval: 300,
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
}
