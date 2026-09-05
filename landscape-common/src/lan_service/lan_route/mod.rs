pub mod dataplane;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::store::storev2::LandscapeStore;
use crate::sys_service::route_service::{LanRouteInfo, LanRouteMode};
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouteLanServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
    pub static_routes: Option<Vec<StaticRouteConfig>>,
}

impl LandscapeStore for RouteLanServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for RouteLanServiceConfig {
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

impl ZoneAwareConfig for RouteLanServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::RouteLan
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticRouteConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub subnet: IpAddr,
    pub sub_prefix: u8,
}

impl StaticRouteConfig {
    pub fn to_lan_info(&self, ifindex: u32, iface_name: &str) -> LanRouteInfo {
        LanRouteInfo {
            ifindex,
            iface_name: iface_name.to_string(),
            iface_ip: self.subnet,
            mac: Some(MacAddr::zero()),
            prefix: self.sub_prefix,
            mode: LanRouteMode::NextHop { next_hop_ip: self.next_hop },
        }
    }
}
