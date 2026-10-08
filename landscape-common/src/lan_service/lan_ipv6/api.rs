use std::collections::HashMap;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::config::ra_flag_default;
use super::{
    DHCPv6ServerConfig, IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6ServiceConfigV2,
    LanPrefixGroupConfig, NaPrefixConfig, PdPrefixRangeConfig, PrefixParentSource, RaPrefixConfig,
    RouterFlags,
};
use crate::service::ServiceConfigError;
use crate::utils::time::get_f64_timestamp;

fn default_lifetime() -> u32 {
    300
}

/// API view of [`PrefixParentSource`]: the `depend_iface` mirror is
/// server-internal (DB write-back for downgraded binaries) and never
/// crosses the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ApiPrefixParentSource {
    Static {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        parent_prefix_len: u8,
    },
    Pd {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        link_id: Uuid,
        #[serde(alias = "planned_parent_prefix_len")]
        expected_pd_len_snapshot: u8,
    },
}

impl From<PrefixParentSource> for ApiPrefixParentSource {
    fn from(value: PrefixParentSource) -> Self {
        match value {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                ApiPrefixParentSource::Static { base_prefix, parent_prefix_len }
            }
            PrefixParentSource::Pd { link_id, expected_pd_len_snapshot, .. } => {
                ApiPrefixParentSource::Pd { link_id, expected_pd_len_snapshot }
            }
        }
    }
}

impl From<ApiPrefixParentSource> for PrefixParentSource {
    fn from(value: ApiPrefixParentSource) -> Self {
        match value {
            ApiPrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                PrefixParentSource::Static { base_prefix, parent_prefix_len }
            }
            ApiPrefixParentSource::Pd { link_id, expected_pd_len_snapshot } => {
                PrefixParentSource::Pd {
                    link_id,
                    depend_iface: String::new(),
                    expected_pd_len_snapshot,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiLanPrefixGroupConfig {
    pub group_id: String,
    pub parent: ApiPrefixParentSource,
    #[serde(default)]
    pub ra: Option<RaPrefixConfig>,
    #[serde(default)]
    pub na: Option<NaPrefixConfig>,
    #[serde(default)]
    pub pd: Option<PdPrefixRangeConfig>,
}

impl From<LanPrefixGroupConfig> for ApiLanPrefixGroupConfig {
    fn from(value: LanPrefixGroupConfig) -> Self {
        Self {
            group_id: value.group_id,
            parent: value.parent.into(),
            ra: value.ra,
            na: value.na,
            pd: value.pd,
        }
    }
}

impl From<ApiLanPrefixGroupConfig> for LanPrefixGroupConfig {
    fn from(value: ApiLanPrefixGroupConfig) -> Self {
        Self {
            group_id: value.group_id,
            parent: value.parent.into(),
            ra: value.ra,
            na: value.na,
            pd: value.pd,
        }
    }
}

/// API view of [`LanIPv6ConfigV2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiLanIPv6ConfigV2 {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mode: IPv6ServiceMode,
    #[serde(default = "default_lifetime")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub ad_interval: u32,
    #[serde(default = "default_lifetime")]
    #[cfg_attr(feature = "openapi", schema(minimum = 60, maximum = 65535))]
    pub lifetime: u32,
    #[serde(default = "ra_flag_default")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ra_flag: RouterFlags,
    #[serde(default)]
    pub prefix_groups: Vec<ApiLanPrefixGroupConfig>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dhcpv6: Option<DHCPv6ServerConfig>,
}

impl From<LanIPv6ConfigV2> for ApiLanIPv6ConfigV2 {
    fn from(value: LanIPv6ConfigV2) -> Self {
        Self {
            mode: value.mode,
            ad_interval: value.ad_interval,
            lifetime: value.lifetime,
            ra_flag: value.ra_flag,
            prefix_groups: value.prefix_groups.into_iter().map(Into::into).collect(),
            dhcpv6: value.dhcpv6,
        }
    }
}

impl From<ApiLanIPv6ConfigV2> for LanIPv6ConfigV2 {
    fn from(value: ApiLanIPv6ConfigV2) -> Self {
        Self {
            mode: value.mode,
            ad_interval: value.ad_interval,
            lifetime: value.lifetime,
            ra_flag: value.ra_flag,
            prefix_groups: value.prefix_groups.into_iter().map(Into::into).collect(),
            dhcpv6: value.dhcpv6,
        }
    }
}

/// API view of [`LanIPv6ServiceConfigV2`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiLanIPv6ServiceConfigV2 {
    pub iface_name: String,
    pub enable: bool,
    pub config: ApiLanIPv6ConfigV2,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl From<LanIPv6ServiceConfigV2> for ApiLanIPv6ServiceConfigV2 {
    fn from(value: LanIPv6ServiceConfigV2) -> Self {
        Self {
            iface_name: value.iface_name,
            enable: value.enable,
            config: value.config.into(),
            update_at: value.update_at,
        }
    }
}

impl From<ApiLanIPv6ServiceConfigV2> for LanIPv6ServiceConfigV2 {
    fn from(value: ApiLanIPv6ServiceConfigV2) -> Self {
        Self {
            iface_name: value.iface_name,
            enable: value.enable,
            config: value.config.into(),
            update_at: value.update_at,
        }
    }
}

/// Mirrors the repo `validate_cross` resolution so the name-keyed
/// `validate_with_pd_context` checks run against real ifaces before the
/// checked save path persists the config.
pub fn fill_pd_depend_ifaces(
    config: &mut LanIPv6ServiceConfigV2,
    links: &HashMap<Uuid, String>,
) -> Result<(), ServiceConfigError> {
    for group in &mut config.config.prefix_groups {
        let PrefixParentSource::Pd { link_id, depend_iface, .. } = &mut group.parent else {
            continue;
        };
        if link_id.is_nil() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "PD parent must reference a wan link (link_id is missing)".to_string(),
            });
        }
        let iface = links.get(link_id).map(String::as_str).ok_or_else(|| {
            ServiceConfigError::InvalidConfig {
                reason: format!("PD parent references unknown wan link {link_id}"),
            }
        })?;
        if depend_iface != iface {
            *depend_iface = iface.to_string();
        }
    }
    Ok(())
}
