pub mod dataplane;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::net::MacAddr;

/// Identity of a registered WAN route target: a managed WAN link (by
/// permanent uuid) or a docker container network namespace (by name).
#[derive(Eq, Hash, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum RouteOwner {
    Link(Uuid),
    Netns(String),
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouteTargetInfo {
    pub weight: u32,
    pub ifindex: u32,
    pub mac: Option<MacAddr>,
    pub default_route: bool,
    pub is_docker: bool,

    pub iface_name: String,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub iface_ip: IpAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub gateway_ip: IpAddr,
}

impl RouteTargetInfo {
    pub fn docker_new(ifindex: u32, iface_name: &str) -> (Self, Self) {
        (
            RouteTargetInfo {
                weight: 0,
                ifindex,
                mac: Some(MacAddr::dummy()),
                default_route: false,
                is_docker: true,
                iface_name: iface_name.to_string(),
                iface_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                gateway_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            RouteTargetInfo {
                weight: 0,
                ifindex,
                mac: Some(MacAddr::dummy()),
                default_route: false,
                is_docker: true,
                iface_name: iface_name.to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
        )
    }
}

#[derive(Eq, Hash, PartialEq, Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum LanRouteMode {
    #[default]
    Reachable,
    NextHop {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        next_hop_ip: IpAddr,
    },
    WanReachable,
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanRouteInfo {
    pub ifindex: u32,
    pub iface_name: String,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub iface_ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub prefix: u8,
    pub mode: LanRouteMode,
}

impl LanRouteInfo {
    pub fn docker_lan(ifindex: u32, iface_name: &str, gateway: IpAddr, prefix: u8) -> Self {
        LanRouteInfo {
            ifindex,
            iface_name: iface_name.to_string(),
            iface_ip: gateway,
            mac: Some(MacAddr::zero()),
            prefix,
            mode: LanRouteMode::Reachable,
        }
    }

    pub fn is_same_subnet(&self, other: &LanRouteInfo) -> bool {
        if self.prefix != other.prefix {
            return false;
        }

        match (self.iface_ip, other.iface_ip) {
            (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
                if self.prefix == 0 {
                    return true;
                }
                if self.prefix >= 32 {
                    return ip1 == ip2;
                }
                let mask = !0u32 << (32 - self.prefix);
                (u32::from(ip1) & mask) == (u32::from(ip2) & mask)
            }
            (IpAddr::V6(ip1), IpAddr::V6(ip2)) => {
                if self.prefix == 0 {
                    return true;
                }
                if self.prefix >= 128 {
                    return ip1 == ip2;
                }
                let mask = !0u128 << (128 - self.prefix);
                (u128::from(ip1) & mask) == (u128::from(ip2) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Eq, Hash, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6RouteKey {
    pub iface_name: String,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub subnet: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanRouteEntry {
    pub owner: RouteOwner,
    pub info: RouteTargetInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Ipv4LanRouteEntry {
    pub owner: String,
    pub info: LanRouteInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Ipv6LanRouteEntry {
    pub key: LanIPv6RouteKey,
    pub info: LanRouteInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouteStatusView {
    pub ipv4_wan: Vec<WanRouteEntry>,
    pub ipv6_wan: Vec<WanRouteEntry>,
    pub ipv4_lan: Vec<Ipv4LanRouteEntry>,
    pub ipv6_lan: Vec<Ipv6LanRouteEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn create_v4_route(ip: [u8; 4], prefix: u8) -> LanRouteInfo {
        LanRouteInfo {
            ifindex: 1,
            iface_name: "test".to_string(),
            iface_ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            mac: None,
            prefix,
            mode: LanRouteMode::Reachable,
        }
    }

    fn create_v6_route(ip: [u16; 8], prefix: u8) -> LanRouteInfo {
        LanRouteInfo {
            ifindex: 1,
            iface_name: "test".to_string(),
            iface_ip: IpAddr::V6(Ipv6Addr::new(
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            )),
            mac: None,
            prefix,
            mode: LanRouteMode::Reachable,
        }
    }

    #[test]
    fn test_same_ipv4_subnet() {
        let route1 = create_v4_route([192, 168, 1, 10], 24);
        let route2 = create_v4_route([192, 168, 1, 20], 24);

        assert!(route1.is_same_subnet(&route2));
        assert!(route2.is_same_subnet(&route1));
    }

    #[test]
    fn test_different_ipv4_subnet() {
        let route1 = create_v4_route([192, 168, 1, 10], 24);
        let route2 = create_v4_route([192, 168, 2, 10], 24);

        assert!(!route1.is_same_subnet(&route2));
        assert!(!route2.is_same_subnet(&route1));
    }

    #[test]
    fn test_ipv4_different_prefix() {
        let route1 = create_v4_route([192, 168, 1, 10], 24);
        let route2 = create_v4_route([192, 168, 1, 10], 16);

        assert!(!route1.is_same_subnet(&route2));
    }

    #[test]
    fn test_ipv4_edge_cases() {
        let route1 = create_v4_route([192, 168, 1, 1], 32);
        let route2 = create_v4_route([192, 168, 1, 1], 32);
        let route3 = create_v4_route([192, 168, 1, 2], 32);

        assert!(route1.is_same_subnet(&route2));
        assert!(!route1.is_same_subnet(&route3));

        let route4 = create_v4_route([192, 168, 1, 1], 0);
        let route5 = create_v4_route([10, 0, 0, 1], 0);
        assert!(route4.is_same_subnet(&route5));
    }

    #[test]
    fn test_same_ipv6_subnet() {
        let route1 = create_v6_route([0x2001, 0xdb8, 0x1234, 0x0001, 0, 0, 0, 0x0001], 64);
        let route2 = create_v6_route([0x2001, 0xdb8, 0x1234, 0x0001, 0, 0, 0, 0x0002], 64);

        assert!(route1.is_same_subnet(&route2));
    }

    #[test]
    fn test_different_ipv6_subnet() {
        let route1 = create_v6_route([0x2001, 0xdb8, 0x1234, 0x0001, 0, 0, 0, 0x0001], 64);
        let route2 = create_v6_route([0x2001, 0xdb8, 0x1234, 0x0002, 0, 0, 0, 0x0001], 64);

        assert!(!route1.is_same_subnet(&route2));
    }

    #[test]
    fn test_mixed_ip_versions() {
        let route_v4 = create_v4_route([192, 168, 1, 1], 24);
        let route_v6 = create_v6_route([0x2001, 0xdb8, 0x1234, 0x0001, 0, 0, 0, 0x0001], 64);

        assert!(!route_v4.is_same_subnet(&route_v6));
        assert!(!route_v6.is_same_subnet(&route_v4));
    }

    #[test]
    fn test_real_world_scenarios() {
        let router1 = create_v4_route([192, 168, 1, 1], 24);
        let computer1 = create_v4_route([192, 168, 1, 100], 24);
        let computer2 = create_v4_route([192, 168, 1, 200], 24);
        let dmz_host = create_v4_route([192, 168, 2, 50], 24);

        assert!(router1.is_same_subnet(&computer1));
        assert!(computer1.is_same_subnet(&computer2));

        assert!(!router1.is_same_subnet(&dmz_host));
        assert!(!computer1.is_same_subnet(&dmz_host));
    }
}
