use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::net_proto::udp::dhcp::DhcpV4Options;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::pppd::PPPoEPlugin;

/// One WAN uplink: a link owns its addressing model and the per-link
/// service sections that used to be separate per-iface config rows
/// (see migration `m20261008_095616_wan_links`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkConfig {
    pub id: Uuid,
    /// Pure remark; the reference key is the uuid.
    #[serde(default)]
    pub name: String,
    /// The kernel interface the link rides on (the attach iface for
    /// ethernet / native PPPoE, the pppX device for pppd).
    pub attach_iface_name: String,
    #[serde(default)]
    pub kind: WanLinkKind,
    #[serde(default)]
    pub v4: WanLinkV4Config,
    #[serde(default)]
    pub pd: WanLinkPdConfig,
    #[serde(default)]
    pub nat: WanLinkNatConfig,
    #[serde(default)]
    pub firewall: WanLinkFirewallConfig,
    #[serde(default)]
    pub mss: WanLinkMssConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for WanLinkConfig {
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanLinkKind {
    #[default]
    Ethernet,
    Pppd {
        ppp_iface_name: String,
        peer_id: String,
        password: String,
        #[serde(default)]
        ac: Option<String>,
        #[serde(default)]
        plugin: PPPoEPlugin,
    },
    PppoeNative {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        requested_mru: u16,
        #[serde(default)]
        ac_name: Option<String>,
        #[serde(default)]
        lcp_echo_interval: Option<u32>,
        #[serde(default)]
        redial_backoff_base_secs: Option<u64>,
    },
}

/// IPv4 acquisition section of a link.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkV4Config {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub model: WanLinkV4Model,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanLinkV4Model {
    #[default]
    Nothing,
    /// Address assigned by the PPP peer via IPCP (pppd / native PPPoE).
    Ipcp {
        #[serde(default)]
        default_router: bool,
    },
    Static {
        #[serde(default)]
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<String>)
        )]
        ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        ipv4_mask: Option<u8>,
        #[serde(default)]
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<String>)
        )]
        ipv6: Option<Ipv6Addr>,
        #[serde(default)]
        default_router: bool,
        #[serde(default)]
        #[cfg_attr(
            feature = "openapi",
            schema(required = true, nullable = true, value_type = Option<String>)
        )]
        default_router_ip: Option<Ipv4Addr>,
    },
    DhcpClient {
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        default_router: bool,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<serde_json::Value>))]
        custome_opts: Vec<DhcpV4Options>,
    },
}

/// DHCPv6 PD client section of a link.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkPdConfig {
    #[serde(default)]
    pub enable: bool,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub mac: MacAddr,
    #[serde(default)]
    pub expected_pd_len: Option<u8>,
}

/// NAT section of a link.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkNatConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<crate::wan_service::nat::PortRange>)
    )]
    pub tcp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<crate::wan_service::nat::PortRange>)
    )]
    pub udp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<crate::wan_service::nat::PortRange>)
    )]
    pub icmp_in_range: Option<Range<u16>>,
}

/// Firewall section of a link.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkFirewallConfig {
    #[serde(default)]
    pub enable: bool,
}

/// MSS clamp section of a link.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkMssConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub clamp_size: Option<u16>,
}

impl ServiceKeyProvider for WanLinkConfig {
    fn service_key(&self) -> String {
        self.id.to_string()
    }
}

crate::impl_trivial_validatable!(WanLinkConfig);
