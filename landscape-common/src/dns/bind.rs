use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

/// DNS servers belonging to one WAN. These are destinations, not source addresses.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsWanServers {
    pub link_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,
}

/// Source-address binding for connections to a DNS upstream. Optional: when
/// both addresses are `None` sockets bind to the OS-chosen source address.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsBindConfig {
    /// Follow this flow's selected WAN, including its source address and device.
    /// None keeps the existing source-address/OS routing behavior.
    #[serde(default)]
    pub follow_flow: Option<u32>,
    /// Optional per-WAN destinations. When nonempty, only the active WAN's
    /// servers are used; the upstream's static ips are never a fallback.
    #[serde(default)]
    pub wan_servers: Vec<DnsWanServers>,
    #[serde(skip)]
    #[cfg_attr(feature = "openapi", schema(ignore))]
    pub resolved_wan: Option<DnsWanBinding>,
    /// Source address for IPv4 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr4: Option<Ipv4Addr>,
    /// Source address for IPv6 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr6: Option<Ipv6Addr>,
}

/// Ephemeral binding resolved by the route service; never persisted or accepted
/// from an API request. Missing families fail closed when follow_flow is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsWanBinding {
    pub ipv4: Option<(String, Ipv4Addr)>,
    pub ipv6: Option<(String, Ipv6Addr)>,
    pub ipv4_link_id: Option<Uuid>,
    pub ipv6_link_id: Option<Uuid>,
}

impl DnsBindConfig {
    /// Select by transport family, independently of the DNS question type.
    /// An IPv4 DNS server can return both A and AAAA answers.
    pub fn server_ips(&self, static_ips: &[IpAddr]) -> Vec<IpAddr> {
        if self.wan_servers.is_empty() {
            return static_ips.to_vec();
        }
        let Some(binding) = self.resolved_wan.as_ref().filter(|_| self.follow_flow.is_some())
        else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for servers in &self.wan_servers {
            for ip in &servers.ips {
                let selected = match ip {
                    IpAddr::V4(_) => {
                        binding.ipv4.is_some() && binding.ipv4_link_id == Some(servers.link_id)
                    }
                    IpAddr::V6(_) => {
                        binding.ipv6.is_some() && binding.ipv6_link_id == Some(servers.link_id)
                    }
                };
                if selected && !result.contains(ip) {
                    result.push(*ip);
                }
            }
        }
        result
    }

    pub fn socket_mark(&self, mark: u32) -> u32 {
        self.follow_flow.map_or(mark, |flow| (mark & !0xff) | (flow & 0xff))
    }

    pub fn source_addr(&self, ipv6: bool) -> Option<std::net::IpAddr> {
        if self.follow_flow.is_some() {
            let binding = self.resolved_wan.as_ref()?;
            if ipv6 {
                binding.ipv6.as_ref().map(|(_, ip)| (*ip).into())
            } else {
                binding.ipv4.as_ref().map(|(_, ip)| (*ip).into())
            }
        } else if ipv6 {
            self.bind_addr6.map(Into::into)
        } else {
            self.bind_addr4.map(Into::into)
        }
    }

    pub fn interface(&self, ipv6: bool) -> Option<&str> {
        let binding = self.resolved_wan.as_ref()?;
        if ipv6 {
            binding.ipv6.as_ref().map(|(name, _)| name.as_str())
        } else {
            binding.ipv4.as_ref().map(|(name, _)| name.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn carrier_servers_follow_each_transport_family_and_fail_closed() {
        let cu = Uuid::new_v4();
        let ct = Uuid::new_v4();
        let ips =
            |values: &[&str]| values.iter().map(|v| v.parse().unwrap()).collect::<Vec<IpAddr>>();
        let static_ips = ips(&["1.0.0.1"]);
        let mut config = DnsBindConfig {
            follow_flow: Some(0),
            wan_servers: vec![
                DnsWanServers {
                    link_id: cu,
                    ips: ips(&["210.21.196.6", "221.5.88.88", "2001:db8:1::53"]),
                },
                DnsWanServers {
                    link_id: ct,
                    ips: ips(&["202.96.128.86", "202.96.128.166", "2001:db8:2::53"]),
                },
            ],
            ..Default::default()
        };
        assert!(config.server_ips(&static_ips).is_empty());
        config.resolved_wan = Some(DnsWanBinding {
            ipv4: Some(("wan-cu".into(), "192.0.2.1".parse().unwrap())),
            ipv6: Some(("wan-ct".into(), "2001:db8::1".parse().unwrap())),
            ipv4_link_id: Some(cu),
            ipv6_link_id: Some(ct),
        });
        assert_eq!(
            config.server_ips(&static_ips),
            ips(&["210.21.196.6", "221.5.88.88", "2001:db8:2::53"])
        );
        config.resolved_wan.as_mut().unwrap().ipv4_link_id = Some(ct);
        assert_eq!(
            config.server_ips(&static_ips),
            ips(&["202.96.128.86", "202.96.128.166", "2001:db8:2::53"])
        );
        config.resolved_wan.as_mut().unwrap().ipv4_link_id = Some(cu);
        config.resolved_wan.as_mut().unwrap().ipv6 = None;
        assert_eq!(config.server_ips(&static_ips), ips(&["210.21.196.6", "221.5.88.88"]));
        config.resolved_wan.as_mut().unwrap().ipv4_link_id = Some(Uuid::new_v4());
        assert!(config.server_ips(&static_ips).is_empty());
        config.follow_flow = None;
        assert!(config.server_ips(&static_ips).is_empty());
        config.wan_servers.clear();
        assert_eq!(config.server_ips(&static_ips), static_ips);
    }

    #[test]
    fn runtime_binding_is_never_persisted_or_accepted_from_json() {
        let config = DnsBindConfig {
            follow_flow: Some(7),
            resolved_wan: Some(DnsWanBinding {
                ipv4: Some(("wan2".into(), "192.0.2.2".parse().unwrap())),
                ipv6: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(config.socket_mark(0x8003), 0x8007);
        assert_eq!(config.interface(false), Some("wan2"));
        assert!(config.source_addr(true).is_none());
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("resolved_wan"));
        let mut json = serde_json::to_value(&config).unwrap();
        json["resolved_wan"] = serde_json::json!({"ipv4": ["evil", "192.0.2.3"]});
        let decoded: DnsBindConfig = serde_json::from_value(json).unwrap();
        assert!(decoded.resolved_wan.is_none());
        assert_eq!(decoded.follow_flow, Some(7));
    }
}
