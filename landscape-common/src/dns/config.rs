use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dns::bind::DnsBindConfig;
use crate::dns::upstream::DnsUpstreamMode;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsUpstreamConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,

    pub name: Option<String>,

    pub remark: String,

    pub mode: DnsUpstreamMode,

    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,

    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub port: Option<u16>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub enable_ip_validation: Option<bool>,

    /// Opt in to the experimental upstream connection pool (default: false).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = true))]
    pub use_experimental_pool: Option<bool>,

    /// Source-address binding for connections to this upstream (optional).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub bind_config: DnsBindConfig,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl DnsUpstreamConfig {
    /// Rule-level WAN selection supplies the binding. An independent group
    /// must not carry a competing flow/source address or nested WAN selector.
    pub fn is_independent_wan_group(&self) -> bool {
        !self.ips.is_empty()
            && self.bind_config.follow_flow.is_none()
            && self.bind_config.wan_servers.is_empty()
            && self.bind_config.bind_addr4.is_none()
            && self.bind_config.bind_addr6.is_none()
    }
}

impl LandscapeDBStore<Uuid> for DnsUpstreamConfig {
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

impl Default for DnsUpstreamConfig {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: None,
            remark: "Landscape Router Default DNS Upstream".to_string(),
            mode: DnsUpstreamMode::Plaintext,
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))],
            enable_ip_validation: None,
            use_experimental_pool: None,
            port: Some(53),
            bind_config: DnsBindConfig::default(),
            update_at: get_f64_timestamp(),
        }
    }
}

impl crate::database::validator::ValidatableConfig for DnsUpstreamConfig {
    fn validate(&self) -> Result<(), crate::service::ServiceConfigError> {
        if self.bind_config.follow_flow.is_some_and(|id| id > 255) {
            return Err(crate::service::ServiceConfigError::InvalidConfig {
                reason: "DNS follow_flow must be between 0 and 255".into(),
            });
        }
        if self.bind_config.follow_flow.is_some()
            && (self.bind_config.bind_addr4.is_some() || self.bind_config.bind_addr6.is_some())
        {
            return Err(crate::service::ServiceConfigError::InvalidConfig {
                reason: "DNS WAN following cannot be combined with a fixed source address".into(),
            });
        }
        if !self.bind_config.wan_servers.is_empty() {
            let invalid = |reason: &str| crate::service::ServiceConfigError::InvalidConfig {
                reason: reason.into(),
            };
            if self.bind_config.follow_flow.is_none() {
                return Err(invalid("Per-WAN DNS servers require a followed flow"));
            }
            let mut links = std::collections::HashSet::new();
            for servers in &self.bind_config.wan_servers {
                if servers.link_id.is_nil() || !links.insert(servers.link_id) {
                    return Err(invalid("Per-WAN DNS requires unique, nonempty WAN IDs"));
                }
                if servers.ips.is_empty()
                    || servers.ips.iter().any(|ip| {
                        ip.is_unspecified()
                            || ip.is_multicast()
                            || ip.is_loopback()
                            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
                            || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
                    })
                {
                    return Err(invalid("Each WAN needs at least one usable DNS server IP"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{database::validator::ValidatableConfig, dns::bind::DnsWanServers};

    #[test]
    fn per_wan_servers_require_binding_unique_links_and_valid_addresses() {
        let mut config = DnsUpstreamConfig::default();
        assert!(config.validate().is_ok());
        config.bind_config.wan_servers = vec![DnsWanServers {
            link_id: Uuid::new_v4(),
            ips: vec!["202.96.128.86".parse().unwrap()],
        }];
        assert!(config.validate().is_err());
        config.bind_config.follow_flow = Some(0);
        assert!(config.validate().is_ok());
        config.bind_config.wan_servers.push(config.bind_config.wan_servers[0].clone());
        assert!(config.validate().is_err());
        config.bind_config.wan_servers.pop();
        for ip in ["0.0.0.0", "::", "127.0.0.1", "224.0.0.1", "255.255.255.255", "fe80::1"] {
            config.bind_config.wan_servers[0].ips = vec![ip.parse().unwrap()];
            assert!(config.validate().is_err(), "{ip}");
        }
        config.bind_config.wan_servers[0].ips.clear();
        assert!(config.validate().is_err());
    }
}
