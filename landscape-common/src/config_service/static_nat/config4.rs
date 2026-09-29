use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::wan_service::nat::config::NatConfig;

use super::config::StaticMapPair;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatV4Target {
    Address {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ipv4: Ipv4Addr,
    },
    Local,
    Device {
        device_id: Uuid,
    },
}

impl StaticNatV4Target {
    pub fn address(ipv4: Ipv4Addr) -> Self {
        Self::Address { ipv4 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticNatMappingV4Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub name: Option<String>,
    pub enable: bool,
    pub remark: String,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub wan_iface_name: Option<String>,
    pub mapping_pair_ports: Vec<StaticMapPair>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatV4Target>,
    pub l4_protocols: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl StaticNatMappingV4Config {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.enable && self.mapping_pair_ports.is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "mapping_pair_ports must not be empty when enabled".to_string(),
            });
        }

        if self.enable {
            match self.lan_target.as_ref() {
                None => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "enabled static NAT mapping must define a LAN target".to_string(),
                    });
                }
                Some(StaticNatV4Target::Device { device_id }) if device_id.is_nil() => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "device target must select a valid enrolled device".to_string(),
                    });
                }
                _ => {}
            }
        }

        for (i, pair) in self.mapping_pair_ports.iter().enumerate() {
            if pair.wan_port == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("mapping_pair_ports[{i}].wan_port must not be 0"),
                });
            }
            if pair.lan_port == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("mapping_pair_ports[{i}].lan_port must not be 0"),
                });
            }
            if self.mapping_pair_ports[..i].iter().any(|prev| prev.wan_port == pair.wan_port) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "mapping_pair_ports[{i}].wan_port {} is duplicated",
                        pair.wan_port
                    ),
                });
            }
        }

        for (i, &proto) in self.l4_protocols.iter().enumerate() {
            if proto != 6 && proto != 17 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("l4_protocols[{i}] ({proto}) must be 6 (TCP) or 17 (UDP)"),
                });
            }
        }

        Ok(())
    }

    pub fn validate_no_dynamic_port_overlap(
        &self,
        nat_config: &NatConfig,
    ) -> Result<(), ServiceConfigError> {
        if !self.enable || self.mapping_pair_ports.is_empty() || self.l4_protocols.is_empty() {
            return Ok(());
        }
        for proto in &self.l4_protocols {
            let range = match *proto {
                6 => &nat_config.tcp_range,
                17 => &nat_config.udp_range,
                _ => continue,
            };
            for pair in &self.mapping_pair_ports {
                if pair.wan_port >= range.start && pair.wan_port <= range.end {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "wan_port {} ({}) overlaps the NAT dynamic port range {}..={}",
                            pair.wan_port,
                            if *proto == 6 { "TCP" } else { "UDP" },
                            range.start,
                            range.end
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

impl LandscapeDBStore<Uuid> for StaticNatMappingV4Config {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV4Config {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Ipv4Addr,
    pub l4_protocols: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> StaticNatMappingV4Config {
        StaticNatMappingV4Config {
            id: Uuid::nil(),
            name: None,
            enable: true,
            remark: String::new(),
            wan_iface_name: Some("eth0".to_string()),
            mapping_pair_ports: vec![StaticMapPair { wan_port: 22, lan_port: 22 }],
            lan_target: Some(StaticNatV4Target::Local),
            l4_protocols: vec![6],
            update_at: 0.0,
        }
    }

    #[test]
    fn duplicate_wan_port_within_a_mapping_is_rejected() {
        let mut config = base_config();
        config.mapping_pair_ports.push(StaticMapPair { wan_port: 22, lan_port: 8080 });

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("is duplicated"));
    }

    #[test]
    fn repeated_lan_port_across_pairs_is_allowed() {
        let mut config = base_config();
        config.mapping_pair_ports.push(StaticMapPair { wan_port: 8080, lan_port: 22 });

        assert!(config.validate().is_ok());
    }

    #[test]
    fn same_wan_port_across_mappings_is_out_of_scope() {
        let mut config = base_config();
        config.mapping_pair_ports = vec![
            StaticMapPair { wan_port: 22, lan_port: 22 },
            StaticMapPair { wan_port: 6443, lan_port: 16443 },
        ];

        assert!(config.validate().is_ok());
    }

    #[test]
    fn wan_port_inside_nat_dynamic_range_is_rejected() {
        let mut config = base_config();
        config.mapping_pair_ports = vec![StaticMapPair { wan_port: 40000, lan_port: 22 }];

        let err = config.validate_no_dynamic_port_overlap(&NatConfig::default()).unwrap_err();
        assert!(err.to_string().contains("overlaps the NAT dynamic port range"));
    }

    #[test]
    fn wan_port_below_dynamic_range_is_allowed() {
        let config = base_config();

        assert!(config.validate_no_dynamic_port_overlap(&NatConfig::default()).is_ok());
    }

    #[test]
    fn dynamic_range_check_is_protocol_aware() {
        let mut config = base_config();
        config.l4_protocols = vec![17];
        config.mapping_pair_ports = vec![StaticMapPair { wan_port: 40000, lan_port: 22 }];

        let nat_config = NatConfig {
            tcp_range: 60000..65535,
            udp_range: 32768..65535,
            ..Default::default()
        };

        assert!(config.validate_no_dynamic_port_overlap(&nat_config).is_err());

        let nat_config = NatConfig {
            tcp_range: 32768..65535,
            udp_range: 40000..65535,
            ..Default::default()
        };
        config.mapping_pair_ports = vec![StaticMapPair { wan_port: 33000, lan_port: 22 }];

        assert!(config.validate_no_dynamic_port_overlap(&nat_config).is_ok());
    }

    #[test]
    fn dynamic_range_check_skips_disabled_mappings() {
        let mut config = base_config();
        config.enable = false;
        config.mapping_pair_ports = vec![StaticMapPair { wan_port: 40000, lan_port: 22 }];

        assert!(config.validate_no_dynamic_port_overlap(&NatConfig::default()).is_ok());
    }
}
