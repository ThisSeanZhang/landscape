use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{
    IfaceZoneType, NetworkIfaceConfig, ServiceKind, ZoneAwareConfig, ZoneRequirement,
};
use crate::database::repository::LandscapeDBStore;
use crate::net_proto::udp::dhcp::DhcpV4Options;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceIpServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub ip_model: IfaceIpModelConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl ServiceKeyProvider for IfaceIpServiceConfig {
    fn service_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for IfaceIpServiceConfig {
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

impl ZoneAwareConfig for IfaceIpServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::IpConfig
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum IfaceIpModelConfig {
    #[default]
    Nothing,
    Static {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true, nullable = true, value_type = Option<String>))]
        default_router_ip: Option<Ipv4Addr>,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        default_router: bool,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true, nullable = true, value_type = Option<String>))]
        ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        ipv4_mask: u8,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true, nullable = true, value_type = Option<String>))]
        ipv6: Option<Ipv6Addr>,
    },
    PPPoE {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        default_router: bool,
        username: String,
        password: String,
        mtu: u32,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = false, nullable = true, value_type = Option<String>))]
        ac_name: Option<String>,
    },
    DhcpClient {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true))]
        default_router: bool,
        hostname: Option<String>,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true, value_type = Vec<serde_json::Value>))]
        custome_opts: Vec<DhcpV4Options>,
    },
}

impl IfaceIpModelConfig {
    pub fn check_iface_status(&self, iface_config: &NetworkIfaceConfig) -> bool {
        match self {
            IfaceIpModelConfig::PPPoE { .. } | IfaceIpModelConfig::DhcpClient { .. } => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan)
            }
            _ => true,
        }
    }
}
