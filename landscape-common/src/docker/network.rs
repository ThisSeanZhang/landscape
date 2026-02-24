use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr};

use crate::{dev::get_interface_index_by_name, net::MacAddr, route::LanRouteInfo};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDockerNetwork {
    // Name
    pub name: String,
    pub id: String,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub driver: Option<String>,
    pub containers: HashMap<String, LandscapeDockerNetworkContainer>,
    pub iface_name: String,
    pub options: HashMap<String, String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub ip_info: Option<LandscapeDockerIpInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDockerNetworkContainer {
    pub name: String,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub mac: Option<MacAddr>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDockerIpInfo {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub subnet_ip: IpAddr,
    pub prefix: u8,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub gateway: IpAddr,
}

impl LandscapeDockerNetwork {
    pub fn convert_to_lan_info(&self) -> Option<LanRouteInfo> {
        let Some(ifindex) = get_interface_index_by_name(&self.iface_name) else {
            tracing::error!("could not read {}'s ifindex", self.iface_name);
            return None;
        };
        // println!("info: {:?}", self);
        let Some(ip_info) = &self.ip_info else {
            tracing::error!("{}'s ip info is empty", self.iface_name);
            return None;
        };

        Some(LanRouteInfo::docker_lan(ifindex, &self.iface_name, ip_info.gateway, ip_info.prefix))
    }
}
