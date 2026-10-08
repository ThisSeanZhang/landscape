use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PortConflictCheckResponse {
    pub conflict: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u16>,
}

use uuid::Uuid;

use super::config::StaticMapPair;
use super::config4::{StaticNatMappingV4Config, StaticNatV4Target};
use super::config6::{StaticNatMappingV6Config, StaticNatV6PortConfig, StaticNatV6Target};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

/// API view of [`StaticNatMappingV4Config`]: the `wan_iface_name` mirror is
/// server-internal (DB write-back for downgraded binaries) and never crosses
/// the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiStaticNatMappingV4Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: Option<String>,
    pub enable: bool,
    pub remark: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true, value_type = Option<String>))]
    pub wan_link_id: Option<Uuid>,
    pub mapping_pair_ports: Vec<StaticMapPair>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatV4Target>,
    pub l4_protocols: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl From<StaticNatMappingV4Config> for ApiStaticNatMappingV4Config {
    fn from(value: StaticNatMappingV4Config) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            remark: value.remark,
            wan_link_id: value.wan_link_id,
            mapping_pair_ports: value.mapping_pair_ports,
            lan_target: value.lan_target,
            l4_protocols: value.l4_protocols,
            update_at: value.update_at,
        }
    }
}

impl From<ApiStaticNatMappingV4Config> for StaticNatMappingV4Config {
    fn from(value: ApiStaticNatMappingV4Config) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            remark: value.remark,
            wan_link_id: value.wan_link_id,
            wan_iface_name: None,
            mapping_pair_ports: value.mapping_pair_ports,
            lan_target: value.lan_target,
            l4_protocols: value.l4_protocols,
            update_at: value.update_at,
        }
    }
}

/// API view of [`StaticNatMappingV6Config`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApiStaticNatMappingV6Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: Option<String>,
    pub enable: bool,
    pub remark: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true, value_type = Option<String>))]
    pub wan_link_id: Option<Uuid>,
    pub port_config: StaticNatV6PortConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatV6Target>,
    pub l4_protocols: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl From<StaticNatMappingV6Config> for ApiStaticNatMappingV6Config {
    fn from(value: StaticNatMappingV6Config) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            remark: value.remark,
            wan_link_id: value.wan_link_id,
            port_config: value.port_config,
            lan_target: value.lan_target,
            l4_protocols: value.l4_protocols,
            update_at: value.update_at,
        }
    }
}

impl From<ApiStaticNatMappingV6Config> for StaticNatMappingV6Config {
    fn from(value: ApiStaticNatMappingV6Config) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enable: value.enable,
            remark: value.remark,
            wan_link_id: value.wan_link_id,
            wan_iface_name: None,
            port_config: value.port_config,
            lan_target: value.lan_target,
            l4_protocols: value.l4_protocols,
            update_at: value.update_at,
        }
    }
}
