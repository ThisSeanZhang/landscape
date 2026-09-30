use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use super::dhcpv6_config::DHCPv6ServerConfig;
use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IPv6ServiceMode {
    #[default]
    Slaac,
    Stateful,
    SlaacDhcpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrefixGroupServiceKind {
    Ra,
    Na,
    IaPd,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouterFlags {
    pub managed_address_config: bool,
    pub other_config: bool,
    pub home_agent: bool,
    pub prf: u8,
    pub nd_proxy: bool,
    pub reserved: u8,
}

impl From<u8> for RouterFlags {
    fn from(byte: u8) -> Self {
        Self {
            managed_address_config: (byte & 0b1000_0000) != 0,
            other_config: (byte & 0b0100_0000) != 0,
            home_agent: (byte & 0b0010_0000) != 0,
            prf: (byte & 0b0001_1000) >> 3,
            nd_proxy: (byte & 0b0000_0100) != 0,
            reserved: byte & 0b0000_0011,
        }
    }
}

impl From<RouterFlags> for u8 {
    fn from(val: RouterFlags) -> Self {
        (val.managed_address_config as u8) << 7
            | (val.other_config as u8) << 6
            | (val.home_agent as u8) << 5
            | (val.prf << 3)
            | (val.nd_proxy as u8) << 2
            | val.reserved
    }
}

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6ConfigV2 {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mode: IPv6ServiceMode,
    // Deprecated: the RA interval is derived from `lifetime` at runtime.
    // Removal is rollback-safe to this version because the serde default restores 300.
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
    pub prefix_groups: Vec<LanPrefixGroupConfig>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dhcpv6: Option<DHCPv6ServerConfig>,
}

fn default_lifetime() -> u32 {
    300
}

impl LanIPv6ConfigV2 {
    pub fn preferred_lifetime(&self) -> u32 {
        self.lifetime
    }

    pub fn valid_lifetime(&self) -> u32 {
        self.preferred_lifetime() * 2
    }

    pub fn icmp_ad_interval(&self) -> u32 {
        self.preferred_lifetime().clamp(60, 600)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6ServiceConfigV2 {
    pub iface_name: String,
    pub enable: bool,
    pub config: LanIPv6ConfigV2,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl ServiceKeyProvider for LanIPv6ServiceConfigV2 {
    fn service_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for LanIPv6ServiceConfigV2 {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

pub fn ra_flag_default() -> RouterFlags {
    0xc0.into()
}

impl ZoneAwareConfig for LanIPv6ServiceConfigV2 {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::LanIpv6
    }
}

crate::impl_trivial_validatable!(LanIPv6ServiceConfigV2);
