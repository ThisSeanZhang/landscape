use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use landscape_macro::{LdCreate, LdUpdate};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::database::validator::ValidatableConfig;
use crate::net::MacAddr;
use crate::net_proto::udp::dhcp::DhcpV4Options;
use crate::service::ServiceConfigError;
use crate::service::manager::ServiceKeyProvider;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::pppd::{PPPDConfig, PPPoEPlugin};

/// Valid chain slots are `1..=LINK_CHAIN_ID_MAX` (`0` means "unassigned").
pub const LINK_CHAIN_ID_MIN: u16 = 1;
pub const LINK_CHAIN_ID_MAX: u16 = 1023;

/// Smallest free chain slot, skipping `used`.
pub fn allocate_link_chain_id(used: impl IntoIterator<Item = u16>) -> Option<u16> {
    let used: std::collections::HashSet<u16> = used.into_iter().collect();
    (LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX).find(|id| !used.contains(id))
}

/// One WAN uplink: a link owns its addressing model and the per-link
/// service sections that used to be separate per-iface config rows
/// (see migration `m20261008_095616_wan_links`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, LdCreate, LdUpdate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    /// Pure remark; the reference key is the uuid.
    #[serde(default)]
    pub name: String,
    /// The kernel interface the link rides on. Always the underlying
    /// physical attach iface; for pppd links the pppX device is carried in
    /// the `Pppd` variant's `ppp_iface_name` (see
    /// `RuntimeWanLinkConfig::section_iface_name`).
    pub attach_iface_name: String,
    /// eBPF WAN chain slot, immutable once assigned; `0` means "unassigned".
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub link_chain_id: u16,
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

impl WanLinkConfig {
    /// True when the link has an acquisition/anchor intent.
    /// - PPP kinds: gated by the service switch (`v4.enable`); PD cannot bring
    ///   the session up on its own.
    /// - Ethernet: v4 or PD (V6-only still anchors the attach iface).
    pub fn active(&self) -> bool {
        match &self.kind {
            WanLinkKind::Pppd { .. } | WanLinkKind::PppoeNative { .. } => self.v4.enable,
            WanLinkKind::Ethernet => self.v4.enable || self.pd.enable,
        }
    }

    /// The net iface this link's references mirror: the ppp device for
    /// pppd links, the attach iface otherwise.
    pub fn section_iface_name(&self) -> &str {
        match &self.kind {
            WanLinkKind::Pppd { ppp_iface_name, .. } => ppp_iface_name,
            WanLinkKind::Ethernet | WanLinkKind::PppoeNative { .. } => &self.attach_iface_name,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkV4Config {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub model: WanLinkV4Model,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkFirewallConfig {
    #[serde(default)]
    pub enable: bool,
}

/// MSS clamp section of a link.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkMssConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub clamp_size: Option<u16>,
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

impl ServiceKeyProvider for WanLinkConfig {
    fn service_key(&self) -> String {
        self.id.to_string()
    }
}

fn validate_nat_range(name: &str, range: &Option<Range<u16>>) -> Result<(), ServiceConfigError> {
    if let Some(range) = range {
        if range.start == 0 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("nat {name} start port must not be 0"),
            });
        }
        if range.start >= range.end {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "nat {name} range invalid: start ({}) must be smaller than end ({})",
                    range.start, range.end
                ),
            });
        }
    }
    Ok(())
}

/// Section-level validation (cross-link rules live in
/// `WanLinkRepository::validate_cross`, injected into the checked write
/// path; they need store access).
impl ValidatableConfig for WanLinkConfig {
    fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.attach_iface_name.is_empty() {
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
            WanLinkKind::Ethernet => {}
            WanLinkKind::Pppd { ppp_iface_name, peer_id, password, ac, plugin } => {
                crate::wan_service::pppd::validate_ppp_iface_name(ppp_iface_name)?;
                if ppp_iface_name == &self.attach_iface_name {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "PPPoE interface name cannot be the same as its attached interface"
                            .to_string(),
                    });
                }
                // Reuse the legacy pppd field checks (peer_id/password/ac).
                PPPDConfig {
                    default_route: false,
                    peer_id: peer_id.clone(),
                    password: password.clone(),
                    ac: ac.clone(),
                    plugin: plugin.clone(),
                }
                .validate()?;
            }
            WanLinkKind::PppoeNative { .. } => {}
        }

        if let Some(expected_pd_len) = self.pd.expected_pd_len
            && !(56..=64).contains(&expected_pd_len)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("expected_pd_len ({expected_pd_len}) must be between 56 and 64"),
            });
        }

        if let Some(clamp_size) = self.mss.clamp_size
            && !(536..=1500).contains(&clamp_size)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("clamp_size ({clamp_size}) must be between 536 and 1500"),
            });
        }

        validate_nat_range("tcp_range", &self.nat.tcp_range)?;
        validate_nat_range("udp_range", &self.nat.udp_range)?;
        validate_nat_range("icmp_in_range", &self.nat.icmp_in_range)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::validator::ValidatableConfig;

    fn minimal() -> WanLinkConfig {
        serde_json::from_value(serde_json::json!({
            "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
            "attach_iface_name": "eth0"
        }))
        .unwrap()
    }

    #[test]
    fn allocate_link_chain_id_picks_smallest_free_slot() {
        assert_eq!(allocate_link_chain_id([]), Some(LINK_CHAIN_ID_MIN));
        assert_eq!(allocate_link_chain_id([1, 2]), Some(3));
        assert_eq!(allocate_link_chain_id([1, 3]), Some(2));
        // 0 is a "needs allocation" signal, never a usable slot.
        assert_eq!(allocate_link_chain_id([0, 1]), Some(2));
        assert_eq!(allocate_link_chain_id([LINK_CHAIN_ID_MAX]), Some(1));
    }

    #[test]
    fn allocate_link_chain_id_returns_none_when_exhausted() {
        assert_eq!(allocate_link_chain_id(LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX), None);
    }

    #[test]
    fn validates_link_chain_id_range() {
        let mut config = minimal();
        config.link_chain_id = 0;
        assert!(config.validate().is_ok(), "0 (unassigned) is allowed");
        config.link_chain_id = LINK_CHAIN_ID_MIN;
        assert!(config.validate().is_ok());
        config.link_chain_id = LINK_CHAIN_ID_MAX;
        assert!(config.validate().is_ok());
        config.link_chain_id = LINK_CHAIN_ID_MAX + 1;
        assert!(config.validate().is_err());
    }
}
