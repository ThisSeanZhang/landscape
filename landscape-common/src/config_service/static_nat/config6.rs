use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv6Addr;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatV6Target {
    Address {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ipv6: Ipv6Addr,
    },
    Local,
    Device {
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = false))]
        device_ids: Vec<Uuid>,
    },
}

impl StaticNatV6Target {
    pub fn address(ipv6: Ipv6Addr) -> Self {
        Self::Address { ipv6 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum StaticNatV6PortConfig {
    All,
    Ports { ports: Vec<u16> },
}

impl Default for StaticNatV6PortConfig {
    fn default() -> Self {
        Self::Ports { ports: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticNatMappingV6Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub remark: String,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub wan_iface_name: Option<String>,
    pub port_config: StaticNatV6PortConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatV6Target>,
    pub l4_protocols: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl StaticNatMappingV6Config {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.enable {
            match self.lan_target.as_ref() {
                None => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "enabled static NAT mapping must define a LAN target".to_string(),
                    });
                }
                Some(StaticNatV6Target::Device { device_ids }) if device_ids.is_empty() => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "device target must select at least one valid enrolled device"
                            .to_string(),
                    });
                }
                Some(StaticNatV6Target::Device { device_ids })
                    if device_ids.iter().any(|id| id.is_nil()) =>
                {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "device target must select a valid enrolled device".to_string(),
                    });
                }
                Some(StaticNatV6Target::Device { device_ids }) => {
                    let mut seen = HashSet::new();
                    for id in device_ids {
                        if !seen.insert(id) {
                            return Err(ServiceConfigError::InvalidConfig {
                                reason: "device target must not contain duplicate devices"
                                    .to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        if self.enable {
            if let StaticNatV6PortConfig::Ports { ports } = &self.port_config {
                if ports.is_empty() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "port_config ports list must not be empty when enabled".to_string(),
                    });
                }
                let mut seen = HashSet::new();
                for (i, &port) in ports.iter().enumerate() {
                    if port == 0 {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!("port_config ports[{i}] must not be 0"),
                        });
                    }
                    if !seen.insert(port) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!("port_config ports[{i}] ({port}) is duplicated"),
                        });
                    }
                }
            }
        }

        if self.enable {
            let is_local_target =
                matches!(self.lan_target.as_ref(), Some(StaticNatV6Target::Local))
                    || matches!(
                        self.lan_target.as_ref(),
                        Some(StaticNatV6Target::Address { ipv6 }) if ipv6.is_unspecified()
                    );
            if matches!(self.port_config, StaticNatV6PortConfig::All) && is_local_target {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "local target does not support opening all ports".to_string(),
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
}

impl LandscapeDBStore<Uuid> for StaticNatMappingV6Config {
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
pub struct RuntimeStaticNatMappingV6Config {
    pub port_config: StaticNatV6PortConfig,
    pub lan_ipv6: Ipv6Addr,
    pub l4_protocols: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_unspecified_address_uses_local_port_validation() {
        let config = StaticNatMappingV6Config {
            id: Uuid::nil(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            port_config: StaticNatV6PortConfig::All,
            lan_target: Some(StaticNatV6Target::address(Ipv6Addr::UNSPECIFIED)),
            l4_protocols: vec![17],
            update_at: 0.0,
        };

        assert!(config.validate().is_err());
    }
}
