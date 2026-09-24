use std::collections::HashSet;
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

pub mod session;
pub mod status;

pub use session::{SessionSignal, SessionState, WanV4Lease};
pub use status::{LinkState, LinkStatus};

pub const MSS_CLAMP_MIN: u16 = 536;
pub const MSS_CLAMP_MAX: u16 = 1500;
pub const PD_LEN_MIN: u8 = 56;
pub const PD_LEN_MAX: u8 = 64;

/// Valid range of the per-link chain id used by the eBPF dispatch map value.
/// `0` is reserved: it means "not yet assigned" and is never a valid chain id.
pub const LINK_CHAIN_ID_MIN: u16 = 1;
pub const LINK_CHAIN_ID_MAX: u16 = 1023;

/// Smallest free link chain id in `[LINK_CHAIN_ID_MIN, LINK_CHAIN_ID_MAX]`,
/// skipping the values in `used`. Returns `None` when the range is exhausted.
pub fn allocate_link_chain_id(used: impl IntoIterator<Item = u16>) -> Option<u16> {
    let used: HashSet<u16> = used.into_iter().collect();
    (LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX).find(|id| !used.contains(id))
}

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

    /// eBPF WAN chain id this link maps to. `0` means "not assigned"; the
    /// backend allocates a unique value in `[LINK_CHAIN_ID_MIN, LINK_CHAIN_ID_MAX]`
    /// right before the row is first inserted and never lets it change afterwards.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub link_chain_id: u16,

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
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = crate::wan_service::nat::PortRange)
    )]
    pub tcp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = crate::wan_service::nat::PortRange)
    )]
    pub udp_range: Option<Range<u16>>,
    #[serde(default)]
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = crate::wan_service::nat::PortRange)
    )]
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

    /// Whether establishing this link's session requires the attach iface to
    /// expose a MAC address.
    ///
    /// - `PppoeNative` always builds raw Ethernet frames, so it needs a MAC.
    /// - An active v4 DHCP client needs a MAC for its client identifier/CHADDR.
    /// - Static uses the MAC opportunistically, pppd does not read it, and the
    ///   Ethernet PD-only anchor needs none.
    pub fn requires_attach_mac(&self) -> bool {
        matches!(self.kind, WanLinkKindConfig::PppoeNative { .. })
            || (self.v4_active() && matches!(self.v4.model, WanV4Model::DhcpClient { .. }))
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

        if self.link_chain_id > LINK_CHAIN_ID_MAX {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "link_chain_id ({}) must be 0 (unassigned) or between {LINK_CHAIN_ID_MIN} and {LINK_CHAIN_ID_MAX}",
                    self.link_chain_id
                ),
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

fn is_ip_mode(kind: &WanLinkKindConfig) -> bool {
    matches!(kind, WanLinkKindConfig::Ethernet | WanLinkKindConfig::PppoeNative { .. })
}

/// Cross-row cardinality rules for links sharing one attach iface:
/// - at most one ip-mode link (`Ethernet` xor `PppoeNative`)
/// - at most one `Pppd` link
/// - `PppoeNative` and `Pppd` are mutually exclusive
/// - `Ethernet` + `Pppd` may coexist
///
/// `others` must already be filtered to the same attach iface and must not
/// contain `config` itself.
pub fn check_link_cardinality(
    config: &WanLinkConfig,
    others: &[WanLinkConfig],
) -> Result<(), ServiceConfigError> {
    use WanLinkKindConfig::{Pppd, PppoeNative};
    for other in others {
        if other.id == config.id {
            continue;
        }
        match (&config.kind, &other.kind) {
            (Pppd { .. }, Pppd { .. }) => {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "another pppd link ({}) already exists on attach iface {}",
                        other.id, config.attach_iface_name
                    ),
                });
            }
            (PppoeNative { .. }, Pppd { .. }) | (Pppd { .. }, PppoeNative { .. }) => {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "pppoe_native and pppd links are mutually exclusive on attach iface {}",
                        config.attach_iface_name
                    ),
                });
            }
            _ if is_ip_mode(&config.kind) && is_ip_mode(&other.kind) => {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "another ip-mode link ({}) already exists on attach iface {}",
                        other.id, config.attach_iface_name
                    ),
                });
            }
            // Ethernet + Pppd is the only allowed pair.
            _ => {}
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
    fn requires_attach_mac_per_kind() {
        let mut config = ethernet_link();
        // Inactive ethernet: nothing to establish.
        assert!(!config.requires_attach_mac());

        // Active DHCP needs a MAC.
        config.v4 = WanV4Config {
            enable: true,
            model: WanV4Model::DhcpClient {
                hostname: None,
                default_router: true,
                custome_opts: vec![],
            },
        };
        assert!(config.requires_attach_mac());

        // Static binds opportunistically.
        config.v4.model = WanV4Model::Static {
            ipv4: Some(std::net::Ipv4Addr::new(192, 0, 2, 10)),
            ipv4_mask: None,
            ipv6: None,
            default_router: true,
            default_router_ip: None,
        };
        assert!(!config.requires_attach_mac());

        // PPPoE always needs a MAC, even PD-only.
        config.kind = WanLinkKindConfig::PppoeNative {
            username: "u".to_string(),
            password: "p".to_string(),
            requested_mru: None,
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        config.v4 = WanV4Config::default();
        assert!(config.requires_attach_mac());

        // pppd does not read the attach MAC.
        config.kind = WanLinkKindConfig::Pppd {
            ppp_iface_name: "ppp0".to_string(),
            peer_id: "u".to_string(),
            password: "p".to_string(),
            ac: None,
            plugin: PPPoEPlugin::default(),
        };
        assert!(!config.requires_attach_mac());
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

    #[test]
    fn allocate_link_chain_id_picks_smallest_free_slot() {
        assert_eq!(allocate_link_chain_id([]), Some(LINK_CHAIN_ID_MIN));
        assert_eq!(allocate_link_chain_id([1, 2]), Some(3));
        assert_eq!(allocate_link_chain_id([1, 3]), Some(2));
        // 0 is reserved and must be ignored even if reported as used.
        assert_eq!(allocate_link_chain_id([0, 1]), Some(2));
        // Out-of-range values do not collide with any valid slot.
        assert_eq!(allocate_link_chain_id([LINK_CHAIN_ID_MAX]), Some(1));
    }

    #[test]
    fn allocate_link_chain_id_returns_none_when_exhausted() {
        let all: Vec<u16> = (LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX).collect();
        assert_eq!(allocate_link_chain_id(all), None);
    }

    #[test]
    fn validates_link_chain_id_range() {
        let mut config = ethernet_link();
        assert!(config.validate().is_ok(), "0 (unassigned) is valid at validate time");

        config.link_chain_id = LINK_CHAIN_ID_MIN;
        assert!(config.validate().is_ok());

        config.link_chain_id = LINK_CHAIN_ID_MAX;
        assert!(config.validate().is_ok());

        config.link_chain_id = LINK_CHAIN_ID_MAX + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_config_leaves_link_chain_id_unassigned() {
        let config: WanLinkConfig =
            serde_json::from_value(serde_json::json!({"attach_iface_name": "wan0"})).unwrap();
        assert_eq!(config.link_chain_id, 0);
    }

    fn pppd_link(id: &str, attach: &str) -> WanLinkConfig {
        WanLinkConfig {
            id: Uuid::parse_str(id).unwrap(),
            attach_iface_name: attach.to_string(),
            kind: WanLinkKindConfig::Pppd {
                ppp_iface_name: "ppp0".to_string(),
                peer_id: "user".to_string(),
                password: "pass".to_string(),
                ac: None,
                plugin: PPPoEPlugin::default(),
            },
            ..Default::default()
        }
    }

    fn pppoe_native_link(id: &str, attach: &str) -> WanLinkConfig {
        WanLinkConfig {
            id: Uuid::parse_str(id).unwrap(),
            attach_iface_name: attach.to_string(),
            kind: WanLinkKindConfig::PppoeNative {
                username: "u".to_string(),
                password: "p".to_string(),
                requested_mru: None,
                ac_name: None,
                lcp_echo_interval: None,
                redial_backoff_base_secs: None,
            },
            ..Default::default()
        }
    }

    const ID_A: &str = "00000000-0000-0000-0000-000000000001";
    const ID_B: &str = "00000000-0000-0000-0000-000000000002";

    #[test]
    fn cardinality_allows_ethernet_plus_pppd() {
        let mut config = ethernet_link();
        config.id = Uuid::parse_str(ID_A).unwrap();
        let others = vec![pppd_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_ok());
    }

    #[test]
    fn cardinality_rejects_duplicate_ip_mode() {
        let mut config = ethernet_link();
        config.id = Uuid::parse_str(ID_A).unwrap();
        let others = vec![pppoe_native_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_err());

        let config = pppoe_native_link(ID_A, "wan0");
        let others = vec![pppoe_native_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_err());
    }

    #[test]
    fn cardinality_rejects_duplicate_pppd() {
        let config = pppd_link(ID_A, "wan0");
        let others = vec![pppd_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_err());
    }

    #[test]
    fn cardinality_rejects_pppoe_native_with_pppd() {
        let config = pppoe_native_link(ID_A, "wan0");
        let others = vec![pppd_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_err());

        let config = pppd_link(ID_A, "wan0");
        let others = vec![pppoe_native_link(ID_B, "wan0")];
        assert!(check_link_cardinality(&config, &others).is_err());
    }

    #[test]
    fn cardinality_ignores_self_and_other_attach_ifaces() {
        let mut config = ethernet_link();
        config.id = Uuid::parse_str(ID_A).unwrap();
        let mut other_iface = config.clone();
        other_iface.attach_iface_name = "wan1".to_string();
        let mut same_id = pppoe_native_link(ID_A, "wan0");
        same_id.attach_iface_name = "wan0".to_string();
        assert!(check_link_cardinality(&config, &[other_iface, same_id]).is_ok());
    }
}
