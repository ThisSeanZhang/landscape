use std::ops::Range;

use uuid::Uuid;

use crate::net::MacAddr;
use crate::wan_service::ipv6_pd::config::DEFAULT_EXPECTED_PD_LEN;
use crate::wan_service::pppd::PPPoEPlugin;

use super::{WanLinkConfig, WanLinkKind, WanLinkV4Model};

/// Default MRU requested from the AC when the stored kind config carries 0.
pub const DEFAULT_REQUESTED_MRU: u16 = 1492;
/// Default MSS clamp size, matching the legacy per-iface service default.
pub const DEFAULT_CLAMP_SIZE: u16 = 1492;
/// Default port range for every NAT protocol, matching `NatConfig::default`.
pub const DEFAULT_NAT_PORT_RANGE_START: u16 = 32768;
pub const DEFAULT_NAT_PORT_RANGE_END: u16 = 65535;

fn default_nat_port_range() -> Range<u16> {
    DEFAULT_NAT_PORT_RANGE_START..DEFAULT_NAT_PORT_RANGE_END
}

/// A [`WanLinkConfig`] with service-level defaults filled in: this is what
/// the link service consumes to start its sub-services. Sections that are
/// optional in the stored JSON (because the migration writes `null`) become
/// concrete values with the legacy per-service defaults here.
#[derive(Debug, Clone)]
pub struct RuntimeWanLinkConfig {
    pub id: Uuid,
    pub name: String,
    pub attach_iface_name: String,
    pub kind: RuntimeWanLinkKind,
    pub v4: RuntimeWanLinkV4Config,
    pub pd: RuntimeWanLinkPdConfig,
    pub nat: RuntimeWanLinkNatConfig,
    pub firewall: RuntimeWanLinkFirewallConfig,
    pub mss: RuntimeWanLinkMssConfig,
}

impl RuntimeWanLinkConfig {
    pub fn from_config(config: &WanLinkConfig) -> Self {
        let kind = match &config.kind {
            WanLinkKind::Ethernet => RuntimeWanLinkKind::Ethernet,
            WanLinkKind::Pppd { ppp_iface_name, peer_id, password, ac, plugin } => {
                RuntimeWanLinkKind::Pppd {
                    ppp_iface_name: ppp_iface_name.clone(),
                    peer_id: peer_id.clone(),
                    password: password.clone(),
                    ac: ac.clone(),
                    plugin: plugin.clone(),
                }
            }
            WanLinkKind::PppoeNative {
                username,
                password,
                requested_mru,
                ac_name,
                lcp_echo_interval,
                redial_backoff_base_secs,
            } => RuntimeWanLinkKind::PppoeNative {
                username: username.clone(),
                password: password.clone(),
                requested_mru: if *requested_mru == 0 {
                    DEFAULT_REQUESTED_MRU
                } else {
                    *requested_mru
                },
                ac_name: ac_name.clone(),
                lcp_echo_interval: *lcp_echo_interval,
                redial_backoff_base_secs: *redial_backoff_base_secs,
            },
        };

        Self {
            id: config.id,
            name: config.name.clone(),
            attach_iface_name: config.attach_iface_name.clone(),
            kind,
            v4: RuntimeWanLinkV4Config {
                enable: config.v4.enable,
                model: config.v4.model.clone(),
            },
            pd: RuntimeWanLinkPdConfig {
                enable: config.pd.enable,
                mac: config.pd.mac,
                expected_pd_len: config.pd.expected_pd_len.unwrap_or(DEFAULT_EXPECTED_PD_LEN),
            },
            nat: RuntimeWanLinkNatConfig {
                enable: config.nat.enable,
                tcp_range: config.nat.tcp_range.clone().unwrap_or_else(default_nat_port_range),
                udp_range: config.nat.udp_range.clone().unwrap_or_else(default_nat_port_range),
                icmp_in_range: config
                    .nat
                    .icmp_in_range
                    .clone()
                    .unwrap_or_else(default_nat_port_range),
            },
            firewall: RuntimeWanLinkFirewallConfig { enable: config.firewall.enable },
            mss: RuntimeWanLinkMssConfig {
                enable: config.mss.enable,
                clamp_size: config.mss.clamp_size.unwrap_or(DEFAULT_CLAMP_SIZE),
            },
        }
    }

    /// The iface the per-link sections (nat / mss / firewall / pd) operate
    /// on: the ppp device for pppd links (it carries the public address),
    /// the attach iface for ethernet and native PPPoE links.
    pub fn section_iface_name(&self) -> &str {
        match &self.kind {
            RuntimeWanLinkKind::Pppd { ppp_iface_name, .. } => ppp_iface_name,
            RuntimeWanLinkKind::Ethernet | RuntimeWanLinkKind::PppoeNative { .. } => {
                &self.attach_iface_name
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum RuntimeWanLinkKind {
    Ethernet,
    Pppd {
        ppp_iface_name: String,
        peer_id: String,
        password: String,
        ac: Option<String>,
        plugin: PPPoEPlugin,
    },
    PppoeNative {
        username: String,
        password: String,
        requested_mru: u16,
        ac_name: Option<String>,
        lcp_echo_interval: Option<u32>,
        redial_backoff_base_secs: Option<u64>,
    },
}

/// The v4 model needs no default filling beyond what serde already applied,
/// but is kept as a runtime section for symmetry with the other sections.
#[derive(Debug, Clone)]
pub struct RuntimeWanLinkV4Config {
    pub enable: bool,
    pub model: WanLinkV4Model,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWanLinkPdConfig {
    pub enable: bool,
    pub mac: MacAddr,
    pub expected_pd_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeWanLinkNatConfig {
    pub enable: bool,
    pub tcp_range: Range<u16>,
    pub udp_range: Range<u16>,
    pub icmp_in_range: Range<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeWanLinkFirewallConfig {
    pub enable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeWanLinkMssConfig {
    pub enable: bool,
    pub clamp_size: u16,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DEFAULT_CLAMP_SIZE, DEFAULT_EXPECTED_PD_LEN, DEFAULT_NAT_PORT_RANGE_END,
        DEFAULT_NAT_PORT_RANGE_START, DEFAULT_REQUESTED_MRU, RuntimeWanLinkConfig,
    };
    use crate::wan_link::WanLinkConfig;

    fn minimal_config() -> WanLinkConfig {
        serde_json::from_value(json!({
            "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
            "attach_iface_name": "eth0",
        }))
        .unwrap()
    }

    #[test]
    fn from_config_fills_all_section_defaults() {
        let runtime = RuntimeWanLinkConfig::from_config(&minimal_config());

        assert_eq!(runtime.pd.expected_pd_len, DEFAULT_EXPECTED_PD_LEN);
        assert_eq!(runtime.mss.clamp_size, DEFAULT_CLAMP_SIZE);
        assert_eq!(runtime.nat.tcp_range.start, DEFAULT_NAT_PORT_RANGE_START);
        assert_eq!(runtime.nat.udp_range.end, DEFAULT_NAT_PORT_RANGE_END);
        assert_eq!(runtime.nat.icmp_in_range.start, DEFAULT_NAT_PORT_RANGE_START);
        assert!(!runtime.pd.enable);
        assert!(!runtime.nat.enable);
        assert!(!runtime.firewall.enable);
        assert!(!runtime.mss.enable);
    }

    #[test]
    fn from_config_keeps_explicit_section_values() {
        let config: WanLinkConfig = serde_json::from_value(json!({
            "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
            "attach_iface_name": "eth0",
            "nat": {
                "enable": true,
                "tcp_range": {"start": 1024, "end": 2048},
                "udp_range": null,
                "icmp_in_range": null
            },
            "mss": {"enable": true, "clamp_size": 1400},
            "pd": {"enable": true, "mac": "02:00:00:00:00:01", "expected_pd_len": 64}
        }))
        .unwrap();

        let runtime = RuntimeWanLinkConfig::from_config(&config);

        assert_eq!(runtime.nat.tcp_range, 1024..2048);
        assert_eq!(runtime.nat.udp_range, 32768..65535);
        assert_eq!(runtime.mss.clamp_size, 1400);
        assert_eq!(runtime.pd.expected_pd_len, 64);
    }

    #[test]
    fn pppoe_native_zero_mru_defaults_to_1492() {
        let config: WanLinkConfig = serde_json::from_value(json!({
            "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
            "attach_iface_name": "eth0",
            "kind": {
                "t": "pppoe_native",
                "username": "u",
                "password": "p",
                "requested_mru": 0,
                "ac_name": null,
                "lcp_echo_interval": null,
                "redial_backoff_base_secs": null
            }
        }))
        .unwrap();

        let runtime = RuntimeWanLinkConfig::from_config(&config);

        match runtime.kind {
            crate::wan_link::RuntimeWanLinkKind::PppoeNative { requested_mru, .. } => {
                assert_eq!(requested_mru, DEFAULT_REQUESTED_MRU);
            }
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn section_iface_is_ppp_device_only_for_pppd_links() {
        let ethernet = RuntimeWanLinkConfig::from_config(&minimal_config());
        assert_eq!(ethernet.section_iface_name(), "eth0");

        let config: WanLinkConfig = serde_json::from_value(json!({
            "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
            "attach_iface_name": "eth0",
            "kind": {
                "t": "pppd",
                "ppp_iface_name": "ppp0",
                "peer_id": "u",
                "password": "p",
                "ac": null,
                "plugin": "rp_pppoe"
            }
        }))
        .unwrap();
        let pppd = RuntimeWanLinkConfig::from_config(&config);
        assert_eq!(pppd.section_iface_name(), "ppp0");
    }
}
