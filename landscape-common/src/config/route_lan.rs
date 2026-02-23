use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::net::MacAddr;
use crate::route::{LanRouteInfo, LanRouteMode};
use crate::utils::time::get_f64_timestamp;
use crate::{database::repository::LandscapeDBStore, store::storev2::LandscapeStore};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/route.d.ts")]
pub struct RouteLanServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,

    /// static route in lan
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
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/route.d.ts")]
pub struct StaticRouteConfig {
    /// Next hop gateway address
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub next_hop: IpAddr,
    /// handle subnet
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub subnet: IpAddr,
    /// prefix
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
