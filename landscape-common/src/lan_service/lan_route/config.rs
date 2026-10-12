use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::service::manager::ServiceKeyProvider;
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

impl ServiceKeyProvider for RouteLanServiceConfig {
    fn service_key(&self) -> String {
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
    pub fn to_lan_info(
        &self,
        ifindex: u32,
        iface_name: &str,
        mac: Option<MacAddr>,
    ) -> LanRouteInfo {
        LanRouteInfo {
            ifindex,
            iface_name: iface_name.to_string(),
            iface_ip: self.subnet,
            mac,
            prefix: self.sub_prefix,
            mode: LanRouteMode::NextHop { next_hop_ip: self.next_hop },
        }
    }
}

crate::impl_trivial_validatable!(RouteLanServiceConfig);

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn route() -> StaticRouteConfig {
        StaticRouteConfig {
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 199)),
            subnet: IpAddr::V4(Ipv4Addr::new(10, 88, 0, 0)),
            sub_prefix: 24,
        }
    }

    #[test]
    fn to_lan_info_uses_egress_iface_mac() {
        let mac = MacAddr::from([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let info = route().to_lan_info(7, "lan0", Some(mac));

        assert_eq!(info.ifindex, 7);
        assert_eq!(info.iface_name, "lan0");
        assert_eq!(info.iface_ip, IpAddr::V4(Ipv4Addr::new(10, 88, 0, 0)));
        assert_eq!(info.prefix, 24);
        assert_eq!(info.mac, Some(mac));
        assert_eq!(
            info.mode,
            LanRouteMode::NextHop {
                next_hop_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 199))
            }
        );
    }

    #[test]
    fn to_lan_info_propagates_missing_mac() {
        let info = route().to_lan_info(7, "lan0", None);
        assert_eq!(info.mac, None);
    }
}
