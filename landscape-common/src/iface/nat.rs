use core::ops::Range;
use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

use crate::config::ConfigId;
use crate::database::repository::LandscapeDBStore;
use crate::iface::config::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum StaticNatError {
    #[error("Static NAT mapping '{0}' not found")]
    #[api_error(id = "static_nat.not_found", status = 404)]
    NotFound(ConfigId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NatServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub nat_config: NatConfig,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeStore for NatServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for NatServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl ZoneAwareConfig for NatServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::WanOrPpp
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::NAT
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NatConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub tcp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub udp_range: Range<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub icmp_in_range: Range<u16>,
}

impl NatConfig {
    fn validate_range(name: &str, range: &Range<u16>) -> Result<(), ServiceConfigError> {
        if range.start == 0 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("{name} start port must be > 0"),
            });
        }
        if range.start >= range.end {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "{name} start ({}) must be less than end ({})",
                    range.start, range.end
                ),
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        Self::validate_range("tcp_range", &self.tcp_range)?;
        Self::validate_range("udp_range", &self.udp_range)?;
        Self::validate_range("icmp_in_range", &self.icmp_in_range)?;
        Ok(())
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_range: 32768..65535,
            udp_range: 32768..65535,
            icmp_in_range: 32768..65535,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticMapPair {
    pub wan_port: u16,
    pub lan_port: u16,
}

// ===========================================================================
// Old unified types below — kept for backward compat with old DB table.
// Will be removed in a future major version cleanup.
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatTarget {
    Address {
        #[serde(default)]
        #[cfg_attr(
            feature = "openapi",
            schema(required = false, nullable = false, value_type = Option<String>)
        )]
        ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        #[cfg_attr(
            feature = "openapi",
            schema(required = false, nullable = false, value_type = Option<String>)
        )]
        ipv6: Option<Ipv6Addr>,
    },
    Local,
    Device {
        device_id: Uuid,
    },
}

impl StaticNatTarget {
    pub fn address(ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Self {
        Self::Address { ipv4, ipv6 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticNatMappingConfig {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub remark: String,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub wan_iface_name: Option<String>,
    pub mapping_pair_ports: Vec<StaticMapPair>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatTarget>,
    pub ipv4_l4_protocol: Vec<u8>,
    pub ipv6_l4_protocol: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingConfig {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Option<Ipv4Addr>,
    pub lan_ipv6: Option<Ipv6Addr>,
    pub ipv4_l4_protocol: Vec<u8>,
    pub ipv6_l4_protocol: Vec<u8>,
}

impl RuntimeStaticNatMappingConfig {
    pub fn convert_to_item(&self) -> Vec<StaticNatMappingItem> {
        let mut result = Vec::with_capacity(4);
        for l4_protocol in &self.ipv4_l4_protocol {
            if let Some(ipv4) = self.lan_ipv4 {
                let items = self.mapping_pair_ports.iter().map(|pair_port| StaticNatMappingItem {
                    wan_port: pair_port.wan_port,
                    lan_port: pair_port.lan_port,
                    lan_ip: IpAddr::V4(ipv4),
                    l4_protocol: *l4_protocol,
                });
                result.extend(items);
            }
        }

        for l4_protocol in &self.ipv6_l4_protocol {
            if let Some(ipv6) = self.lan_ipv6 {
                let items = self.mapping_pair_ports.iter().map(|pair_port| StaticNatMappingItem {
                    wan_port: pair_port.wan_port,
                    lan_port: pair_port.lan_port,
                    lan_ip: IpAddr::V6(ipv6),
                    l4_protocol: *l4_protocol,
                });

                result.extend(items);
            }
        }
        result
    }
}

impl StaticNatMappingConfig {
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
                Some(StaticNatTarget::Device { device_id }) if device_id.is_nil() => {
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
        }

        for (i, &proto) in self.ipv4_l4_protocol.iter().enumerate() {
            if proto != 6 && proto != 17 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("ipv4_l4_protocol[{i}] ({proto}) must be 6 (TCP) or 17 (UDP)"),
                });
            }
        }
        for (i, &proto) in self.ipv6_l4_protocol.iter().enumerate() {
            if proto != 6 && proto != 17 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("ipv6_l4_protocol[{i}] ({proto}) must be 6 (TCP) or 17 (UDP)"),
                });
            }
        }

        if self.enable {
            let target = self
                .lan_target
                .as_ref()
                .expect("enabled static NAT mapping must define LAN target before protocol checks");
            if !self.ipv4_l4_protocol.is_empty() && !target.supports_ipv4_config() {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "enabled IPv4 static NAT mapping must resolve to an IPv4 target"
                        .to_string(),
                });
            }
            if !self.ipv6_l4_protocol.is_empty() && !target.supports_ipv6_config() {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "enabled IPv6 static NAT mapping must resolve to an IPv6 target"
                        .to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn convert_to_item(&self) -> Vec<StaticNatMappingItem> {
        let (lan_ipv4, lan_ipv6) = match &self.lan_target {
            Some(StaticNatTarget::Address { ipv4, ipv6 }) => (*ipv4, *ipv6),
            Some(StaticNatTarget::Local) => {
                (Some(Ipv4Addr::UNSPECIFIED), Some(Ipv6Addr::UNSPECIFIED))
            }
            Some(StaticNatTarget::Device { .. }) | None => (None, None),
        };

        RuntimeStaticNatMappingConfig {
            mapping_pair_ports: self.mapping_pair_ports.clone(),
            lan_ipv4,
            lan_ipv6,
            ipv4_l4_protocol: self.ipv4_l4_protocol.clone(),
            ipv6_l4_protocol: self.ipv6_l4_protocol.clone(),
        }
        .convert_to_item()
    }
}

impl StaticNatTarget {
    fn supports_ipv4_config(&self) -> bool {
        match self {
            StaticNatTarget::Address { ipv4, .. } => ipv4.is_some(),
            StaticNatTarget::Local | StaticNatTarget::Device { .. } => true,
        }
    }

    fn supports_ipv6_config(&self) -> bool {
        match self {
            StaticNatTarget::Address { ipv6, .. } => ipv6.is_some(),
            StaticNatTarget::Local | StaticNatTarget::Device { .. } => true,
        }
    }
}

impl LandscapeDBStore<Uuid> for StaticNatMappingConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct StaticNatMappingItem {
    pub wan_port: u16,
    pub lan_port: u16,
    pub lan_ip: IpAddr,
    pub l4_protocol: u8,
}

// ===========================================================================
// New V4/V6-separated types below.
// ===========================================================================

// --- StaticNatV4Target ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatV4Target {
    Address {
        #[cfg_attr(
            feature = "openapi",
            schema(value_type = String)
        )]
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

// --- staticNatMappingV4Config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticNatMappingV4Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
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

// --- RuntimeStaticNatMappingV4Config ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV4Config {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Ipv4Addr,
    pub l4_protocols: Vec<u8>,
}

// --- StaticNatV6Target ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatV6Target {
    Address {
        #[cfg_attr(
            feature = "openapi",
            schema(value_type = String)
        )]
        ipv6: Ipv6Addr,
    },
    Local,
    Device {
        device_id: Uuid,
    },
}

impl StaticNatV6Target {
    pub fn address(ipv6: Ipv6Addr) -> Self {
        Self::Address { ipv6 }
    }
}

// --- StaticNatMappingV6Config ---

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
    pub mapping_pair_ports: Vec<StaticMapPair>,
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
                Some(StaticNatV6Target::Device { device_id }) if device_id.is_nil() => {
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

// --- RuntimeStaticNatMappingV6Config ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV6Config {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv6: Ipv6Addr,
    pub l4_protocols: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::{StaticMapPair, StaticNatMappingConfig, StaticNatTarget};

    fn base_config() -> StaticNatMappingConfig {
        StaticNatMappingConfig {
            id: uuid::Uuid::nil(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 80, lan_port: 8080 }],
            lan_target: Some(StaticNatTarget::Address {
                ipv4: Some("192.0.2.10".parse().unwrap()),
                ipv6: None,
            }),
            ipv4_l4_protocol: vec![6],
            ipv6_l4_protocol: vec![],
            update_at: 0.0,
        }
    }

    #[test]
    fn enabled_static_nat_requires_target() {
        let mut config = base_config();
        config.lan_target = None;

        assert!(config.validate().is_err());
    }

    #[test]
    fn ipv6_protocol_requires_ipv6_target_for_address_mode() {
        let mut config = base_config();
        config.ipv6_l4_protocol = vec![17];

        assert!(config.validate().is_err());
    }

    #[test]
    fn ipv4_only_device_target_passes_config_validation() {
        let mut config = base_config();
        config.lan_target = Some(StaticNatTarget::Device { device_id: uuid::Uuid::new_v4() });

        assert!(config.validate().is_ok());
    }
}
