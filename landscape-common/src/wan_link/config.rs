use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

use super::runtime::{DEFAULT_HEALTH_INTERVAL_SECS, DEFAULT_HEALTH_TIMEOUT_MS};

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
    #[serde(default)]
    pub health_check: WanLinkHealthCheckConfig,
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
    /// Enabled probe families need evidence. An explicitly disabled family
    /// follows the other family's verdict; route availability is still separate.
    pub fn validate_failover_health(&self) -> Result<(), ServiceConfigError> {
        // An administratively stopped WAN has no routes and is skipped by
        // failover. Allow maintenance without first removing every reference;
        // enabling the WAN again runs the full health validation below.
        if !self.active() {
            return Ok(());
        }
        let (v4, v6) = self.health_check.probe_families();
        let health = &self.health_check;
        // Static.ipv6 is a legacy field ignored by the IPv4 runner. PD is
        // the supported source of an IPv6 address/session on this link.
        let ipv6_enabled = self.pd.enable;
        let usable = (self.v4.enable && health.ipv4_probe_enabled && v4)
            || (ipv6_enabled && health.ipv6_probe_enabled && v6);
        if !health.enable
            || !usable
            || (self.v4.enable && health.ipv4_probe_enabled && !v4)
            || (ipv6_enabled && health.ipv6_probe_enabled && !v6)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "WAN '{}' requires enabled health checks, at least one usable probe family and targets for each enabled probe switch before automatic failover (IPv4 probe: {v4}, IPv6 probe: {v6}); configure missing targets or disable that family's probe switch to follow the other family",
                    self.attach_iface_name,
                ),
            });
        }
        Ok(())
    }

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

/// Maximum configured probe targets of a health check.
pub const MAX_HEALTH_TARGETS: usize = 4;

/// Health check section of a link: probes the link's connectivity through
/// its own iface/source and reports a debounced verdict to the route
/// service. Disabled by default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanLinkHealthCheckConfig {
    #[serde(default)]
    pub enable: bool,
    /// When disabled, inherit the IPv6 probe verdict without probing IPv4.
    #[serde(default = "probe_enabled_by_default")]
    pub ipv4_probe_enabled: bool,
    /// When disabled, inherit the IPv4 probe verdict without probing IPv6.
    #[serde(default = "probe_enabled_by_default")]
    pub ipv6_probe_enabled: bool,
    /// Probe method with its targets.
    #[serde(default)]
    pub probe: WanHealthProbeConfig,
    /// Seconds between probe rounds; `None` = 10.
    #[serde(default)]
    pub interval_secs: Option<u16>,
    /// Per-probe timeout in milliseconds; `None` = 1000.
    #[serde(default)]
    pub timeout_ms: Option<u16>,
    /// Consecutive failed rounds before flipping to `Unhealthy`;
    /// `None` = 3.
    #[serde(default)]
    pub failure_threshold: Option<u8>,
    /// Consecutive successful rounds required to recover from
    /// `Unhealthy`; `None` = 3.
    #[serde(default)]
    pub recovery_threshold: Option<u8>,
    /// Probe targets that must answer for a round to succeed; `None` = 1.
    #[serde(default)]
    pub reliability: Option<u8>,
}

fn probe_enabled_by_default() -> bool {
    true
}

impl Default for WanLinkHealthCheckConfig {
    fn default() -> Self {
        Self {
            enable: false,
            ipv4_probe_enabled: true,
            ipv6_probe_enabled: true,
            probe: Default::default(),
            interval_secs: None,
            timeout_ms: None,
            failure_threshold: None,
            recovery_threshold: None,
            reliability: None,
        }
    }
}

impl WanLinkHealthCheckConfig {
    pub fn probe_families(&self) -> (bool, bool) {
        match &self.probe {
            WanHealthProbeConfig::Multi { groups } => (
                groups.iter().any(|g| g.targets.iter().any(|p| p.address().is_ipv4())),
                groups.iter().any(|g| g.targets.iter().any(|p| p.address().is_ipv6())),
            ),
            WanHealthProbeConfig::Icmp { targets, probe_gateway } => {
                (*probe_gateway || targets.iter().any(|ip| ip.is_ipv4()), false)
            }
            WanHealthProbeConfig::Dns { .. } | WanHealthProbeConfig::Http { .. } => (true, false),
        }
    }
}

/// Probe method of a health check; each variant owns its target
/// representation. ICMP, DNS and HTTP are supported as separate
/// (purely additive) variants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanHealthProbeConfig {
    /// Every group for an address family must pass; each group has its own quorum.
    Multi { groups: Vec<WanProbeGroup> },
    /// Resolve an A record through this WAN's chosen IPv4 DNS server.
    Dns {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        server: std::net::Ipv4Addr,
        domain: String,
    },
    /// HTTP(S) GET, including DNS resolution, confined to this WAN.
    Http {
        url: String,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        dns_server: std::net::Ipv4Addr,
    },

    /// ICMP echo bound to the section iface and source address.
    Icmp {
        /// Probe targets; v1 accepts IPv4 only. Empty means only the
        /// gateway (if `probe_gateway`) is probed. At most
        /// [`MAX_HEALTH_TARGETS`] targets may be configured.
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
        targets: Vec<IpAddr>,
        /// Additionally probe the session's default gateway.
        #[serde(default)]
        probe_gateway: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WanProbeGroup {
    pub name: String,
    pub quorum: u8,
    pub targets: Vec<WanProbeTarget>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WanProbeTarget {
    Icmp {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        address: IpAddr,
    },
    Dns {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        server: IpAddr,
        domain: String,
    },
    Http {
        url: String,
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        dns_server: IpAddr,
    },
}

impl WanProbeTarget {
    pub fn address(&self) -> IpAddr {
        match self {
            Self::Icmp { address } => *address,
            Self::Dns { server, .. } => *server,
            Self::Http { dns_server, .. } => *dns_server,
        }
    }
}

pub fn validate_probe_groups(groups: &[WanProbeGroup]) -> Result<(), ServiceConfigError> {
    let invalid = |reason: &str| ServiceConfigError::InvalidConfig { reason: reason.into() };
    if groups.is_empty() || groups.len() > 4 {
        return Err(invalid("configure between 1 and 4 probe groups"));
    }
    for group in groups {
        if group.targets.is_empty()
            || group.targets.len() > MAX_HEALTH_TARGETS
            || group.quorum == 0
            || usize::from(group.quorum) > group.targets.len()
        {
            return Err(invalid(
                "each probe group needs 1..4 targets and quorum within its target count",
            ));
        }
        let ipv6 = group.targets[0].address().is_ipv6();
        let mut unique = std::collections::HashSet::new();
        for target in &group.targets {
            let ip = target.address();
            if ip.is_ipv6() != ipv6
                || ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || matches!(ip, IpAddr::V4(v) if v.is_broadcast())
                || (matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local())
                    && !matches!(target, WanProbeTarget::Icmp { .. }))
            {
                return Err(invalid(
                    "probe targets in each group must use one address family and routable unicast addresses",
                ));
            }
            if !unique.insert(serde_json::to_string(target).unwrap()) {
                return Err(invalid("duplicate probe targets cannot count toward quorum"));
            }
            match target {
                WanProbeTarget::Dns { domain, .. }
                    if domain.trim().is_empty()
                        || hickory_proto::rr::Name::from_ascii(domain).is_err() =>
                {
                    return Err(invalid("invalid DNS probe domain"));
                }
                WanProbeTarget::Http { url, .. } => {
                    let valid = url::Url::parse(url).is_ok_and(|url| {
                        matches!(url.scheme(), "http" | "https")
                            && url.host_str().is_some()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && match url.host() {
                                Some(url::Host::Ipv4(_)) => !ipv6,
                                Some(url::Host::Ipv6(_)) => ipv6,
                                _ => true,
                            }
                    });
                    if !valid {
                        return Err(invalid("HTTP probe URL must match its DNS address family"));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

impl Default for WanHealthProbeConfig {
    fn default() -> Self {
        Self::Icmp { targets: Vec::new(), probe_gateway: false }
    }
}

fn validate_health_dns_server(server: std::net::Ipv4Addr) -> Result<(), ServiceConfigError> {
    if server.is_unspecified()
        || server.is_loopback()
        || server.is_multicast()
        || server.is_broadcast()
    {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "health_check requires a unicast upstream IPv4 DNS server".into(),
        });
    }
    Ok(())
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

        let health = &self.health_check;
        let (v4_probe, v6_probe) = health.probe_families();
        if health.enable
            && !(health.ipv4_probe_enabled && v4_probe || health.ipv6_probe_enabled && v6_probe)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "health_check needs at least one enabled probe family with targets or probe_gateway".into(),
            });
        }
        let target_count = match &health.probe {
            WanHealthProbeConfig::Multi { groups } => {
                validate_probe_groups(groups)?;
                1 // group quorums are independent from legacy reliability
            }
            WanHealthProbeConfig::Icmp { targets, probe_gateway } => {
                if targets.iter().any(|target| !target.is_ipv4()) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "health_check icmp targets must be IPv4 addresses".to_string(),
                    });
                }
                if health.enable && targets.is_empty() && !*probe_gateway {
                    return Err(ServiceConfigError::InvalidConfig {
                reason: "health_check enabled but nothing to probe: set targets or probe_gateway"
                    .to_string(),
            });
                }
                if targets.len() > MAX_HEALTH_TARGETS {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "health_check icmp targets exceed the maximum of {MAX_HEALTH_TARGETS}"
                        ),
                    });
                }
                targets.len() + usize::from(*probe_gateway)
            }
            WanHealthProbeConfig::Dns { server, domain } => {
                validate_health_dns_server(*server)?;
                if domain.trim().is_empty() || hickory_proto::rr::Name::from_ascii(domain).is_err()
                {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "health_check DNS domain is invalid".into(),
                    });
                }
                1
            }
            WanHealthProbeConfig::Http { url, dns_server } => {
                validate_health_dns_server(*dns_server)?;
                let valid = url::Url::parse(url).is_ok_and(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && !matches!(url.host(), Some(url::Host::Ipv6(_)))
                });
                if !valid {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "health_check URL must be an absolute HTTP(S) URL".into(),
                    });
                }
                1
            }
        };
        if let Some(reliability) = health.reliability {
            if !(1..=100).contains(&reliability) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "health_check reliability ({reliability}) must be between 1 and 100"
                    ),
                });
            }
            if !matches!(health.probe, WanHealthProbeConfig::Multi { .. })
                && target_count > 0
                && reliability as usize > target_count
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "health_check reliability ({reliability}) must not exceed the target count ({target_count})"
                    ),
                });
            }
        }
        if let Some(interval_secs) = health.interval_secs
            && interval_secs == 0
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "health_check interval_secs must not be 0".to_string(),
            });
        }
        if let Some(timeout_ms) = health.timeout_ms
            && !(1..=10000).contains(&timeout_ms)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "health_check timeout_ms ({timeout_ms}) must be between 1 and 10000"
                ),
            });
        }
        if let Some(threshold) = health.failure_threshold
            && !(1..=100).contains(&threshold)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "health_check failure_threshold ({threshold}) must be between 1 and 100"
                ),
            });
        }
        if let Some(threshold) = health.recovery_threshold
            && !(1..=100).contains(&threshold)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "health_check recovery_threshold ({threshold}) must be between 1 and 100"
                ),
            });
        }
        let interval_secs = health.interval_secs.unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS);
        let timeout_ms = health.timeout_ms.unwrap_or(DEFAULT_HEALTH_TIMEOUT_MS);
        if u32::from(timeout_ms) >= u32::from(interval_secs) * 1000 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "health_check timeout_ms ({timeout_ms}) must be smaller than interval_secs ({interval_secs}) in milliseconds"
                ),
            });
        }

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
    fn legacy_static_ipv6_cannot_supply_a_followed_probe_family() {
        let mut config = minimal();
        config.v4.enable = true;
        config.v4.model = WanLinkV4Model::Static {
            ipv4: Some("192.0.2.2".parse().unwrap()),
            ipv4_mask: Some(24),
            ipv6: Some("2001:db8::2".parse().unwrap()),
            default_router: true,
            default_router_ip: Some("192.0.2.1".parse().unwrap()),
        };
        config.health_check.enable = true;
        config.health_check.ipv4_probe_enabled = false;
        config.health_check.probe = WanHealthProbeConfig::Multi {
            groups: vec![WanProbeGroup {
                name: "IPv6".into(),
                quorum: 1,
                targets: vec![WanProbeTarget::Icmp { address: "2001:db8::1".parse().unwrap() }],
            }],
        };
        assert!(config.validate().is_ok());
        assert!(config.validate_failover_health().is_err());
        config.pd.enable = true;
        assert!(config.validate_failover_health().is_ok());
    }

    #[test]
    fn administratively_disabled_wan_is_allowed_but_reenable_revalidates_health() {
        let mut config = minimal();
        config.kind = WanLinkKind::PppoeNative {
            username: "fixture".into(),
            password: "fixture".into(),
            requested_mru: 1492,
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        config.v4.model = WanLinkV4Model::Ipcp { default_router: true };
        assert!(!config.active());
        assert!(config.validate_failover_health().is_ok());
        // PD must not allow an administratively stopped PPP session to run.
        config.pd.enable = true;
        assert!(!config.active());
        assert!(config.validate_failover_health().is_ok());
        config.v4.enable = true;
        assert!(config.active());
        assert!(config.validate_failover_health().is_err());
        config.health_check.enable = true;
        config.health_check.ipv6_probe_enabled = false;
        config.health_check.probe = WanHealthProbeConfig::Dns {
            server: "192.0.2.53".parse().unwrap(),
            domain: "example.com".into(),
        };
        assert!(config.validate_failover_health().is_ok());
    }

    #[test]
    fn automatic_failover_requires_probes_for_enabled_families() {
        let mut config = minimal();
        config.v4.enable = true;
        config.health_check.enable = true;
        config.health_check.probe = WanHealthProbeConfig::Dns {
            server: "223.5.5.5".parse().unwrap(),
            domain: "www.baidu.com".into(),
        };
        assert!(config.validate_failover_health().is_ok());
        config.pd.enable = true;
        assert!(config.validate_failover_health().is_err());
        config.health_check.probe = WanHealthProbeConfig::Multi {
            groups: vec![
                WanProbeGroup {
                    name: "v4".into(),
                    quorum: 1,
                    targets: vec![WanProbeTarget::Icmp { address: "223.5.5.5".parse().unwrap() }],
                },
                WanProbeGroup {
                    name: "v6".into(),
                    quorum: 1,
                    targets: vec![WanProbeTarget::Icmp {
                        address: "2400:3200::1".parse().unwrap(),
                    }],
                },
            ],
        };
        assert!(config.validate_failover_health().is_ok());
        config.health_check.enable = false;
        assert!(config.validate_failover_health().is_err());
    }

    #[test]
    fn probe_switches_default_on_and_explicit_off_is_preserved() {
        let old: WanLinkHealthCheckConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(old, WanLinkHealthCheckConfig::default());
        assert!(old.ipv4_probe_enabled && old.ipv6_probe_enabled);
        let mut config = minimal();
        config.v4.enable = true;
        config.pd.enable = true;
        config.health_check.enable = true;
        config.health_check.probe = WanHealthProbeConfig::Dns {
            server: "223.5.5.5".parse().unwrap(),
            domain: "www.baidu.com".into(),
        };
        assert!(config.validate_failover_health().is_err());
        config.health_check.ipv6_probe_enabled = false;
        assert!(config.validate_failover_health().is_ok());
        let roundtrip: WanLinkConfig =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert!(!roundtrip.health_check.ipv6_probe_enabled);
        config.health_check.ipv4_probe_enabled = false;
        assert!(config.validate().is_err());
        assert!(config.validate_failover_health().is_err());
        config.health_check.ipv6_probe_enabled = true;
        assert!(config.validate().is_err(), "legacy IPv4 target cannot drive IPv6-only probes");
        config.health_check.probe = WanHealthProbeConfig::Multi {
            groups: vec![WanProbeGroup {
                name: "IPv6".into(),
                quorum: 1,
                targets: vec![WanProbeTarget::Icmp { address: "2400:3200::1".parse().unwrap() }],
            }],
        };
        assert!(config.validate_failover_health().is_ok());
        config.pd.enable = false;
        assert!(
            config.validate_failover_health().is_err(),
            "cannot follow a family with no address acquisition"
        );
    }

    #[test]
    fn link_local_ipv6_is_supported_for_scoped_icmp_probes() {
        let group = WanProbeGroup {
            name: "gateway".into(),
            quorum: 1,
            targets: vec![WanProbeTarget::Icmp { address: "fe80::1".parse().unwrap() }],
        };
        assert!(validate_probe_groups(&[group]).is_ok());
        let group = WanProbeGroup {
            name: "DNS".into(),
            quorum: 1,
            targets: vec![WanProbeTarget::Dns {
                server: "fe80::1".parse().unwrap(),
                domain: "example.com".into(),
            }],
        };
        assert!(validate_probe_groups(&[group]).is_err());
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

    #[test]
    fn multi_probe_validates_quorum_and_address_family() {
        let mut config = minimal();
        config.health_check.enable = true;
        let v4 = WanProbeTarget::Dns {
            server: "223.5.5.5".parse().unwrap(),
            domain: "www.baidu.com".into(),
        };
        let v6 = WanProbeTarget::Icmp { address: "2400:3200::1".parse().unwrap() };
        let group = |targets, quorum| WanProbeGroup { name: "test".into(), targets, quorum };
        config.health_check.probe = WanHealthProbeConfig::Multi {
            groups: vec![group(vec![v4.clone()], 1), group(vec![v6.clone()], 1)],
        };
        assert!(config.validate().is_ok(), "separate IPv4 and IPv6 groups are valid");
        for groups in [
            vec![],
            vec![group(vec![], 1)],
            vec![group(vec![v4.clone()], 0)],
            vec![group(vec![v4.clone()], 2)],
            vec![group(vec![v4.clone(), v4.clone()], 1)],
            vec![group(vec![v4, v6], 1)],
        ] {
            config.health_check.probe = WanHealthProbeConfig::Multi { groups };
            assert!(config.validate().is_err(), "reject impossible or ambiguous group");
        }
    }

    #[test]
    fn application_health_probe_validation() {
        let mut config = minimal();
        config.health_check.enable = true;
        config.health_check.probe = WanHealthProbeConfig::Dns {
            server: "223.5.5.5".parse().unwrap(),
            domain: "www.baidu.com".into(),
        };
        assert!(config.validate().is_ok());
        config.health_check.reliability = Some(2);
        assert!(config.validate().is_err(), "single application probe has reliability one");
        config.health_check.reliability = Some(1);
        for url in ["https://www.baidu.com", "http://example.com/health"] {
            config.health_check.probe = WanHealthProbeConfig::Http {
                url: url.into(),
                dns_server: "223.5.5.5".parse().unwrap(),
            };
            assert!(config.validate().is_ok());
        }
        for url in
            ["file:///etc/passwd", "https://", "http://[::1]", "http://user:password@example.com"]
        {
            config.health_check.probe = WanHealthProbeConfig::Http {
                url: url.into(),
                dns_server: "223.5.5.5".parse().unwrap(),
            };
            assert!(config.validate().is_err(), "invalid probe URL: {url}");
        }
    }

    #[test]
    fn health_check_validation_rejects_bad_sections() {
        let mut config = minimal();
        config.health_check.enable = true;
        config.health_check.probe = WanHealthProbeConfig::Icmp {
            targets: vec![
                IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            probe_gateway: true,
        };
        config.health_check.reliability = Some(2);
        config.health_check.interval_secs = Some(30);
        config.health_check.timeout_ms = Some(800);
        config.health_check.failure_threshold = Some(5);
        config.health_check.recovery_threshold = Some(2);
        assert!(config.validate().is_ok(), "a fully populated section is valid");

        let mut config = minimal();
        config.health_check.probe = WanHealthProbeConfig::Icmp {
            targets: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            probe_gateway: false,
        };
        assert!(config.validate().is_err(), "v6 targets are rejected in v1");

        let mut config = minimal();
        config.health_check.enable = true;
        assert!(config.validate().is_err(), "enabled without targets or probe_gateway is rejected");

        config.health_check.probe =
            WanHealthProbeConfig::Icmp { targets: vec![], probe_gateway: true };
        assert!(config.validate().is_ok(), "gateway-only probing is valid");
        config.health_check.reliability = Some(2);
        assert!(config.validate().is_err(), "gateway-only probing allows at most reliability 1");

        let mut config = minimal();
        config.health_check.reliability = Some(0);
        assert!(config.validate().is_err(), "reliability 0 is rejected");

        let mut config = minimal();
        config.health_check.probe = WanHealthProbeConfig::Icmp {
            targets: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            probe_gateway: false,
        };
        config.health_check.reliability = Some(2);
        assert!(config.validate().is_err(), "reliability above explicit targets is rejected");

        let mut config = minimal();
        config.health_check.probe = WanHealthProbeConfig::Icmp {
            targets: (0..MAX_HEALTH_TARGETS as u8)
                .map(|i| IpAddr::V4(Ipv4Addr::new(1, 1, 1, i)))
                .collect(),
            probe_gateway: true,
        };
        config.health_check.reliability = Some(MAX_HEALTH_TARGETS as u8 + 1);
        assert!(config.validate().is_ok(), "MAX_HEALTH_TARGETS targets plus gateway is valid");

        config.health_check.probe = WanHealthProbeConfig::Icmp {
            targets: (0..=MAX_HEALTH_TARGETS as u8)
                .map(|i| IpAddr::V4(Ipv4Addr::new(1, 1, 1, i)))
                .collect(),
            probe_gateway: false,
        };
        config.health_check.reliability = Some(1);
        assert!(config.validate().is_err(), "more than MAX_HEALTH_TARGETS targets is rejected");

        let mut config = minimal();
        config.health_check.interval_secs = Some(0);
        assert!(config.validate().is_err(), "interval 0 is rejected");

        let mut config = minimal();
        config.health_check.timeout_ms = Some(15000);
        assert!(config.validate().is_err(), "timeout beyond 10s is rejected");

        let mut config = minimal();
        config.health_check.interval_secs = Some(2);
        config.health_check.timeout_ms = Some(2000);
        assert!(config.validate().is_err(), "timeout >= interval is rejected");

        let mut config = minimal();
        config.health_check.failure_threshold = Some(0);
        assert!(config.validate().is_err(), "failure_threshold 0 is rejected");

        let mut config = minimal();
        config.health_check.recovery_threshold = Some(0);
        assert!(config.validate().is_err(), "recovery_threshold 0 is rejected");
    }
}
