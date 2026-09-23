use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::net::MacAddr;
use crate::net_proto::udp::dhcp::DhcpV4Options;
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::pppd::{validate_ppp_iface_name, PPPoEPlugin};

pub const MSS_CLAMP_MIN: u16 = 536;
pub const MSS_CLAMP_MAX: u16 = 1500;
pub const PD_LEN_MIN: u8 = 56;
pub const PD_LEN_MAX: u8 = 64;

/// A single WAN uplink: one session (ethernet / native PPPoE / pppd) plus the
/// sub-services that ride on it.
///
/// Identity & references:
/// - `id` is the permanent identity and the only reference key: it is the
///   route owner written into `IpRouteService`, and what flow rules and DDNS
///   jobs reference. Renaming never breaks references.
/// - `name` is a free-form remark (not unique, not referenced).
///
/// There is deliberately no link-level switch: a link establishes only when it
/// has an acquisition intent (`v4_active() || pd_active()`).
///
/// Cross-row cardinality rules (enforced by the manager, they need DB access):
/// - at most one ip-mode link (`Ethernet` xor `PppoeNative`) per attach iface
/// - at most one `Pppd` link per attach iface
/// - `PppoeNative` and `Pppd` are mutually exclusive on the same attach iface
/// - `Ethernet` and `Pppd` may coexist (matches the legacy capability)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,

    /// Pure remark. Not a reference key.
    #[serde(default)]
    pub name: String,

    pub attach_iface_name: String,

    #[serde(default)]
    pub kind: WanLinkKindConfig,

    #[serde(default)]
    pub v4: WanV4Config,

    #[serde(default)]
    pub pd: WanPdConfig,

    #[serde(default)]
    pub nat: WanNatConfig,

    #[serde(default)]
    pub firewall: WanFirewallConfig,

    #[serde(default)]
    pub mss: WanMssConfig,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeStore for WanLinkConfig {
    fn get_store_key(&self) -> String {
        self.id.to_string()
    }
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

impl ZoneAwareConfig for WanLinkConfig {
    fn iface_name(&self) -> &str {
        &self.attach_iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::WanLink
    }
}

/// Session type of the link and its session-scoped parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanLinkKindConfig {
    /// IPoE: no session establishment, the attach iface itself is the link
    /// (`net_iface` = attach iface, `v6_ready` is always true).
    #[default]
    Ethernet,
    /// In-process PPPoE client (eBPF datapath) on the attach iface.
    /// The v4 address comes from the session's IPCP negotiation
    /// (`v4.model = Ipcp`), v6 capability from IPv6CP.
    PppoeNative {
        username: String,
        password: String,
        /// Requested MRU. `None` → runtime default (1492).
        #[serde(default)]
        requested_mru: Option<u16>,
        #[serde(default)]
        ac_name: Option<String>,
        /// LCP echo keepalive interval in seconds. `None` → default 20.
        #[serde(default)]
        lcp_echo_interval: Option<u64>,
        /// Base backoff (seconds) between redial attempts. `None` → default 300.
        #[serde(default)]
        redial_backoff_base_secs: Option<u64>,
    },
    /// External pppd daemon creating the virtual `ppp_iface_name` device.
    Pppd {
        /// Kernel device name pppd creates (constrained charset, <= 15 chars).
        /// Deliberately separate from `name`: this is a kernel constraint,
        /// not a user label.
        ppp_iface_name: String,
        peer_id: String,
        password: String,
        #[serde(default)]
        ac: Option<String>,
        #[serde(default)]
        plugin: PPPoEPlugin,
    },
}

impl WanLinkKindConfig {
    /// The network interface this link's sub-services attach to at runtime:
    /// ethernet / pppoe_native → the attach iface; pppd → the virtual device.
    pub fn net_iface_name(&self, attach_iface_name: &str) -> String {
        match self {
            WanLinkKindConfig::Pppd { ppp_iface_name, .. } => ppp_iface_name.clone(),
            _ => attach_iface_name.to_string(),
        }
    }

    pub fn is_ppp(&self) -> bool {
        matches!(self, WanLinkKindConfig::PppoeNative { .. } | WanLinkKindConfig::Pppd { .. })
    }
}

/// IPv4 acquisition. Mode + independent pause switch: `enable = false`
/// preserves the configured model untouched (legacy `IfaceIpServiceConfig`
/// semantics), `model = Nothing` means "not configured".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanV4Config {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub model: WanV4Model,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanV4Model {
    #[default]
    Nothing,
    Static {
        /// `None` = do not assign an address (legacy semantics).
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        ipv4: Option<Ipv4Addr>,
        /// `None` → runtime default 24.
        #[serde(default)]
        ipv4_mask: Option<u8>,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
        ipv6: Option<Ipv6Addr>,
        #[serde(default)]
        default_router: bool,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
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
    /// Address comes from the PPP session's IPCP negotiation.
    /// Only valid on PPP kinds. A PD-only PPP link uses `Nothing` instead:
    /// the session still negotiates IPCP but no default route is registered
    /// and NAT never activates.
    Ipcp {
        #[serde(default)]
        default_router: bool,
    },
}

/// IPv6 prefix delegation (DHCPv6 IA_PD). Single mode, so no model enum.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanPdConfig {
    #[serde(default)]
    pub enable: bool,
    /// DHCPv6 client DUID source MAC.
    #[serde(default)]
    pub mac: MacAddr,
    /// `None` → runtime default 60.
    #[serde(default)]
    pub expected_pd_len: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanNatConfig {
    #[serde(default)]
    pub enable: bool,
    /// `None` → runtime default 32768..65535.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub tcp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub udp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub icmp_in_range: Option<Range<u16>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanFirewallConfig {
    #[serde(default)]
    pub enable: bool,
}

/// MSS clamping. `clamp_size = None` means auto-derive from the session MTU
/// (PPP kinds only). Explicitly configured values are never reinterpreted:
/// the migration maps every legacy row verbatim to `Some(value)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanMssConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub clamp_size: Option<u16>,
}

impl WanLinkConfig {
    /// The kernel interface this link presents at runtime.
    pub fn net_iface_name(&self) -> String {
        self.kind.net_iface_name(&self.attach_iface_name)
    }

    pub fn v4_active(&self) -> bool {
        self.v4.enable && !matches!(self.v4.model, WanV4Model::Nothing)
    }

    pub fn pd_active(&self) -> bool {
        self.pd.enable
    }

    /// A link establishes only if it has an acquisition intent (v4 or PD).
    pub fn active(&self) -> bool {
        self.v4_active() || self.pd_active()
    }

    /// Structural validation. Zone and cross-link cardinality checks live in
    /// the manager (they need iface/DB lookups).
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.attach_iface_name.trim().is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "attach_iface_name must not be empty".to_string(),
            });
        }

        match &self.kind {
            WanLinkKindConfig::Ethernet => {}
            WanLinkKindConfig::PppoeNative { username, password, .. } => {
                check_credential("username", username)?;
                check_credential("password", password)?;
            }
            WanLinkKindConfig::Pppd { ppp_iface_name, peer_id, password, .. } => {
                validate_ppp_iface_name(ppp_iface_name)?;
                check_credential("peer_id", peer_id)?;
                check_credential("password", password)?;
            }
        }

        match &self.v4.model {
            WanV4Model::Nothing => {}
            WanV4Model::Static { ipv4_mask, .. } => {
                if !self.kind.is_ppp() {
                    if let Some(mask) = ipv4_mask {
                        if *mask > 32 {
                            return Err(ServiceConfigError::InvalidConfig {
                                reason: format!("ipv4_mask ({mask}) must be between 0 and 32"),
                            });
                        }
                    }
                } else {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "v4 static mode is only valid on an ethernet link".to_string(),
                    });
                }
            }
            WanV4Model::DhcpClient { .. } => {
                if self.kind.is_ppp() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "v4 dhcp client mode is only valid on an ethernet link".to_string(),
                    });
                }
            }
            WanV4Model::Ipcp { .. } => {
                if !self.kind.is_ppp() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "v4 ipcp mode requires a ppp link".to_string(),
                    });
                }
            }
        }

        if let Some(len) = self.pd.expected_pd_len {
            if !(PD_LEN_MIN..=PD_LEN_MAX).contains(&len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("expected_pd_len ({len}) must be between 56 and 64"),
                });
            }
        }

        check_nat_range("tcp_range", &self.nat.tcp_range)?;
        check_nat_range("udp_range", &self.nat.udp_range)?;
        check_nat_range("icmp_in_range", &self.nat.icmp_in_range)?;

        if let Some(clamp) = self.mss.clamp_size {
            if !(MSS_CLAMP_MIN..=MSS_CLAMP_MAX).contains(&clamp) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "clamp_size ({clamp}) must be between {MSS_CLAMP_MIN} and {MSS_CLAMP_MAX}"
                    ),
                });
            }
        }
        if self.mss.enable && !self.kind.is_ppp() && self.mss.clamp_size.is_none() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "mss auto-derive requires a ppp link: set an explicit clamp_size"
                    .to_string(),
            });
        }

        Ok(())
    }
}

fn check_credential(field: &str, val: &str) -> Result<(), ServiceConfigError> {
    if val.is_empty() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!("{field} must not be empty"),
        });
    }
    if val.len() > 256 {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!("{field} exceeds 256 chars"),
        });
    }
    if val.contains('\n') || val.contains('\r') || val.contains('"') {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!("{field} contains forbidden characters (newline or quote)"),
        });
    }
    Ok(())
}

fn check_nat_range(name: &str, range: &Option<Range<u16>>) -> Result<(), ServiceConfigError> {
    if let Some(range) = range {
        if range.start == 0 || range.start >= range.end {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "nat {name} range ({}..{}) is invalid: need 0 < start < end",
                    range.start, range.end
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_link() -> WanLinkConfig {
        WanLinkConfig {
            attach_iface_name: "wan0".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_config_decodes_with_all_sections_disabled() {
        let config: WanLinkConfig =
            serde_json::from_value(serde_json::json!({"attach_iface_name": "wan0"})).unwrap();

        assert_eq!(config.kind, WanLinkKindConfig::Ethernet);
        assert_eq!(config.v4, WanV4Config::default());
        assert_eq!(config.pd, WanPdConfig::default());
        assert_eq!(config.nat, WanNatConfig::default());
        assert_eq!(config.firewall, WanFirewallConfig::default());
        assert_eq!(config.mss, WanMssConfig::default());
        assert!(!config.active());
        assert_eq!(config.net_iface_name(), "wan0");
    }

    #[test]
    fn store_key_is_uuid_string() {
        let config = ethernet_link();
        assert_eq!(config.get_store_key(), config.id.to_string());
    }

    #[test]
    fn gate_requires_v4_or_pd() {
        let mut config = ethernet_link();
        assert!(!config.active());

        config.v4.enable = true;
        assert!(!config.active(), "enabled Nothing must not count");

        config.v4.model = WanV4Model::DhcpClient {
            hostname: None,
            default_router: true,
            custome_opts: vec![],
        };
        assert!(config.active());

        config.v4.enable = false;
        assert!(!config.active());

        config.pd.enable = true;
        assert!(config.active(), "PD alone must start the link");
    }

    #[test]
    fn net_iface_resolution_per_kind() {
        let mut config = ethernet_link();
        assert_eq!(config.net_iface_name(), "wan0");

        config.kind = WanLinkKindConfig::Pppd {
            ppp_iface_name: "ppp0".to_string(),
            peer_id: "user".to_string(),
            password: "pass".to_string(),
            ac: None,
            plugin: PPPoEPlugin::default(),
        };
        assert_eq!(config.net_iface_name(), "ppp0");

        config.kind = WanLinkKindConfig::PppoeNative {
            username: "user".to_string(),
            password: "pass".to_string(),
            requested_mru: None,
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        assert_eq!(config.net_iface_name(), "wan0");
    }

    #[test]
    fn kind_serde_tags() {
        let kind = WanLinkKindConfig::PppoeNative {
            username: "u".to_string(),
            password: "p".to_string(),
            requested_mru: Some(1492),
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        let value = serde_json::to_value(&kind).unwrap();
        assert_eq!(value["t"], "pppoe_native");

        let model = WanV4Model::Ipcp { default_router: true };
        let value = serde_json::to_value(&model).unwrap();
        assert_eq!(value["t"], "ipcp");
    }

    #[test]
    fn rejects_mode_kind_mismatch() {
        let mut config = ethernet_link();
        config.v4.model = WanV4Model::Ipcp { default_router: true };
        assert!(config.validate().is_err(), "ipcp on ethernet must fail");

        let mut config = ethernet_link();
        config.kind = WanLinkKindConfig::PppoeNative {
            username: "u".to_string(),
            password: "p".to_string(),
            requested_mru: None,
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        config.v4.model = WanV4Model::DhcpClient {
            hostname: None,
            default_router: true,
            custome_opts: vec![],
        };
        assert!(config.validate().is_err(), "dhcp on ppp must fail");
    }

    #[test]
    fn rejects_mss_auto_on_ethernet() {
        let mut config = ethernet_link();
        config.mss.enable = true;
        config.mss.clamp_size = None;
        assert!(config.validate().is_err());

        config.mss.clamp_size = Some(1452);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validates_pd_len_and_nat_ranges() {
        let mut config = ethernet_link();
        config.pd.expected_pd_len = Some(55);
        assert!(config.validate().is_err());

        config.pd.expected_pd_len = Some(64);
        config.nat.tcp_range = Some(0..100);
        assert!(config.validate().is_err());
        config.nat.tcp_range = Some(100..100);
        assert!(config.validate().is_err());
        config.nat.tcp_range = Some(32768..65535);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn clamp_bounds() {
        let mut config = ethernet_link();
        config.mss.clamp_size = Some(100);
        assert!(config.validate().is_err());
        config.mss.clamp_size = Some(536);
        assert!(config.validate().is_ok());
    }
}
