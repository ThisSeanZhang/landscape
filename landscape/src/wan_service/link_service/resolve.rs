use landscape_common::dev::LandscapeInterface;
use landscape_common::wan_service::link::{
    WanLinkConfig, WanLinkKindConfig, WanNatConfig, WanV4Model,
};
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::pppd::PPPDConfig;

use super::drivers::{SessionSpec, StaticSpec};

pub const DEFAULT_V4_MASK: u8 = 24;
pub const DEFAULT_PPP_MSS_CLAMP: u16 = 1492;
pub const DEFAULT_PD_LEN: u8 = 60;

/// Runtime view of the persisted NAT section: unset ranges fall back to the
/// legacy defaults. Resolution happens per start and is never written back.
pub fn resolve_nat(config: &WanNatConfig) -> NatConfig {
    let defaults = NatConfig::default();
    NatConfig {
        tcp_range: config.tcp_range.clone().unwrap_or(defaults.tcp_range),
        udp_range: config.udp_range.clone().unwrap_or(defaults.udp_range),
        icmp_in_range: config.icmp_in_range.clone().unwrap_or(defaults.icmp_in_range),
    }
}

/// MSS clamp value: explicit values pass through verbatim (never
/// reinterpreted); auto-derive is only reachable on PPP kinds where the
/// session MTU bounds it (validate() rejects auto on ethernet).
pub fn resolve_mss_clamp(link: &WanLinkConfig) -> u16 {
    if let Some(clamp) = link.mss.clamp_size {
        return clamp;
    }
    match &link.kind {
        WanLinkKindConfig::PppoeNative { requested_mru, .. } => {
            requested_mru.unwrap_or(crate::wan_service::pppoe_client::DEFAULT_CLIENT_MRU)
        }
        WanLinkKindConfig::Pppd { .. } => DEFAULT_PPP_MSS_CLAMP,
        WanLinkKindConfig::Ethernet => {
            tracing::warn!(
                link_id = %link.id,
                "mss auto-derive on an ethernet link should have been rejected; using default"
            );
            DEFAULT_PPP_MSS_CLAMP
        }
    }
}

pub fn resolve_pppoe_client_config(
    link: &WanLinkConfig,
    iface: &LandscapeInterface,
    default_router: bool,
) -> crate::wan_service::pppoe_client::PPPoEClientConfig {
    let WanLinkKindConfig::PppoeNative {
        username,
        password,
        requested_mru,
        ac_name,
        lcp_echo_interval,
        redial_backoff_base_secs,
    } = &link.kind
    else {
        unreachable!("caller checked the kind")
    };
    crate::wan_service::pppoe_client::PPPoEClientConfig {
        link_id: link.id,
        index: iface.index,
        iface_name: iface.name.clone(),
        iface_mac: iface.mac.expect("caller checked the attach iface mac"),
        peer_id: username.clone(),
        password: password.clone(),
        default_router,
        requested_mru: requested_mru
            .unwrap_or(crate::wan_service::pppoe_client::DEFAULT_CLIENT_MRU),
        ac_name: ac_name.clone(),
        lcp_echo_interval: *lcp_echo_interval,
        redial_backoff_base_secs: *redial_backoff_base_secs,
    }
}

pub fn resolve_pppd_config(link: &WanLinkConfig, default_route: bool) -> PPPDConfig {
    let WanLinkKindConfig::Pppd { peer_id, password, ac, plugin, .. } = &link.kind else {
        unreachable!("caller checked the kind")
    };
    PPPDConfig {
        default_route,
        peer_id: peer_id.clone(),
        password: password.clone(),
        ac: ac.clone(),
        plugin: plugin.clone(),
    }
}

/// Build the fully-resolved session/v4 acquisition spec for one link start.
///
/// Resolution rules:
/// - ethernet without v4 intent → `SessionSpec::None`: the session driver
///   publishes `Ready { lease: None }` off the attach iface being present, and
///   the PD section rides that synthesized anchor (PD-only ethernet)
/// - PPP kinds always establish the session (PD rides on it); without v4
///   intent the session runs but registers no default route
/// - static with `ipv4 = None` keeps the legacy "assign nothing" semantics
pub fn resolve_session_spec(link: &WanLinkConfig, iface: &LandscapeInterface) -> SessionSpec {
    if !link.v4_active() {
        return match &link.kind {
            WanLinkKindConfig::Ethernet => SessionSpec::None,
            WanLinkKindConfig::PppoeNative { .. } => {
                SessionSpec::PppoeNative(Box::new(resolve_pppoe_client_config(link, iface, false)))
            }
            WanLinkKindConfig::Pppd { .. } => SessionSpec::Pppd {
                attach_iface_name: link.attach_iface_name.clone(),
                ppp_iface_name: link.net_iface_name(),
                config: resolve_pppd_config(link, false),
            },
        };
    }

    match (&link.kind, &link.v4.model) {
        (
            WanLinkKindConfig::Ethernet,
            WanV4Model::Static {
                ipv4,
                ipv4_mask,
                ipv6,
                default_router,
                default_router_ip,
            },
        ) => {
            let Some(ipv4) = ipv4 else {
                // Legacy semantics: static model with no address does nothing.
                return SessionSpec::None;
            };
            SessionSpec::Static(StaticSpec {
                ipv4: *ipv4,
                mask: ipv4_mask.unwrap_or(DEFAULT_V4_MASK),
                ipv6: *ipv6,
                default_router: *default_router,
                default_router_ip: *default_router_ip,
            })
        }
        (WanLinkKindConfig::Ethernet, WanV4Model::DhcpClient { hostname, default_router, .. }) => {
            SessionSpec::Dhcp {
                hostname: hostname.clone(),
                default_router: *default_router,
            }
        }
        (WanLinkKindConfig::PppoeNative { .. }, WanV4Model::Ipcp { default_router }) => {
            SessionSpec::PppoeNative(Box::new(resolve_pppoe_client_config(
                link,
                iface,
                *default_router,
            )))
        }
        (WanLinkKindConfig::Pppd { .. }, WanV4Model::Ipcp { default_router }) => {
            SessionSpec::Pppd {
                attach_iface_name: link.attach_iface_name.clone(),
                ppp_iface_name: link.net_iface_name(),
                config: resolve_pppd_config(link, *default_router),
            }
        }
        // validate() rejects every other combination.
        _ => SessionSpec::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pppoe(requested_mru: Option<u16>) -> WanLinkConfig {
        WanLinkConfig {
            attach_iface_name: "wan0".to_string(),
            kind: WanLinkKindConfig::PppoeNative {
                username: "u".to_string(),
                password: "p".to_string(),
                requested_mru,
                ac_name: None,
                lcp_echo_interval: None,
                redial_backoff_base_secs: None,
            },
            ..Default::default()
        }
    }

    #[test]
    fn mss_clamp_uses_explicit_value_then_derives_from_ppp_mru() {
        // An explicit value is used verbatim, regardless of kind.
        let mut explicit = pppoe(None);
        explicit.mss.clamp_size = Some(1400);
        assert_eq!(resolve_mss_clamp(&explicit), 1400);

        // `None` on a PPP link derives from the requested MRU.
        assert_eq!(resolve_mss_clamp(&pppoe(Some(1400))), 1400);
        // ... falling back to the runtime default when the MRU is unset.
        assert_eq!(
            resolve_mss_clamp(&pppoe(None)),
            crate::wan_service::pppoe_client::DEFAULT_CLIENT_MRU
        );
    }
}
