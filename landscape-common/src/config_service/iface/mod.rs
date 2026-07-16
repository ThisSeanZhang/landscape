use crate::database::repository::LandscapeDBStore;
use crate::utils::time::get_f64_timestamp;
use crate::{store::storev2::LandscapeStore, LANDSCAPE_DEFAULT_LAN_NAME};
use sea_orm::{prelude::StringLen, DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NetworkIfaceConfig {
    pub name: String,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub create_dev_type: CreateDevType,
    pub controller_name: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub zone_type: IfaceZoneType,
    #[serde(default = "yes")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub enable_in_boot: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub wifi_mode: WifiMode,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub xps_rps: Option<IfaceCpuSoftBalance>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeStore for NetworkIfaceConfig {
    fn get_store_key(&self) -> String {
        self.name.clone()
    }
}

impl LandscapeDBStore<String> for NetworkIfaceConfig {
    fn get_id(&self) -> String {
        self.name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

fn yes() -> bool {
    true
}

impl NetworkIfaceConfig {
    pub fn get_iface_name(&self) -> String {
        self.name.clone()
    }

    pub fn crate_default_br_lan() -> NetworkIfaceConfig {
        NetworkIfaceConfig::crate_bridge(
            LANDSCAPE_DEFAULT_LAN_NAME.into(),
            Some(IfaceZoneType::Lan),
        )
    }

    pub fn crate_bridge(name: String, zone_type: Option<IfaceZoneType>) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name,
            create_dev_type: CreateDevType::Bridge,
            controller_name: None,
            enable_in_boot: true,
            zone_type: zone_type.unwrap_or_default(),
            wifi_mode: WifiMode::default(),
            xps_rps: None,
            update_at: get_f64_timestamp(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum CreateDevType {
    #[default]
    NoNeedToCreate,
    Bridge,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum WifiMode {
    #[default]
    Undefined,
    Client,
    #[serde(rename = "ap")]
    AP,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[derive(EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(100))", rename_all = "snake_case")]
pub enum IfaceZoneType {
    #[default]
    Undefined,
    Wan,
    Lan,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IfaceCpuSoftBalance {
    pub xps: String,
    pub rps: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRequirement {
    WanOnly,
    LanOnly,
    WanOrLan,
    WanOrPpp,
    LanOrUndefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    IpConfig,
    #[serde(rename = "pppoe")]
    PPPoE,
    NAT,
    Firewall,
    MssClamp,
    Ipv6Pd,
    RouteWan,
    DhcpV4,
    LanIpv6,
    RouteLan,
    WiFi,
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpConfig => write!(f, "IP Config"),
            Self::PPPoE => write!(f, "PPPoE"),
            Self::NAT => write!(f, "NAT"),
            Self::Firewall => write!(f, "Firewall"),
            Self::MssClamp => write!(f, "MSS Clamp"),
            Self::Ipv6Pd => write!(f, "IPv6 PD"),
            Self::RouteWan => write!(f, "Route WAN"),
            Self::DhcpV4 => write!(f, "DHCPv4"),
            Self::LanIpv6 => write!(f, "LAN IPv6"),
            Self::RouteLan => write!(f, "Route LAN"),
            Self::WiFi => write!(f, "WiFi"),
        }
    }
}

pub trait ZoneAwareConfig {
    fn iface_name(&self) -> &str;
    fn zone_requirement() -> ZoneRequirement;
    fn service_kind() -> ServiceKind;
}
