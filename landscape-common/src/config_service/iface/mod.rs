pub mod config;

use serde::Serialize;

pub use config::*;

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
    WanLink,
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
            Self::WanLink => write!(f, "WAN Link"),
        }
    }
}

pub trait ZoneAwareConfig {
    fn iface_name(&self) -> &str;
    fn zone_requirement() -> ZoneRequirement;
    fn service_kind() -> ServiceKind;
}
