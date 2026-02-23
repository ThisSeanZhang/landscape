use std::collections::HashSet;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
pub struct IPV6RAServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: IPV6RAConfig,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<String> for IPV6RAServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum IPV6RaConfigSource {
    Static(IPv6RaStaticConfig),
    Pd(IPv6RaPdConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
pub struct IPv6RaStaticConfig {
    /// Base Prefix
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub base_prefix: Ipv6Addr,

    /// subnet prefix length default 64
    pub sub_prefix_len: u8,

    /// index of subnet
    pub sub_index: u32,

    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
pub struct IPv6RaPdConfig {
    pub depend_iface: String,

    // default 64
    pub prefix_len: u8,
    pub subnet_index: u32,

    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
pub struct IPV6RAConfig {
    /// Router Advertisement Interval
    pub ad_interval: u32,
    /// Router Advertisement Flag
    #[serde(default = "ra_flag_default")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ra_flag: RouterFlags,
    /// Ip Source
    pub source: Vec<IPV6RaConfigSource>,
}

impl IPV6RAConfig {
    pub fn validate(&self) -> Result<(), String> {
        let mut base_prefixes = HashSet::<Ipv6Addr>::new();
        let mut depend_ifaces = HashSet::<String>::new();
        let mut sub_indices = HashSet::<u32>::new();

        for src in &self.source {
            match src {
                IPV6RaConfigSource::Static(cfg) => {
                    if !base_prefixes.insert(cfg.base_prefix) {
                        return Err(format!("Duplicate base_prefix found: {}", cfg.base_prefix));
                    }

                    if !sub_indices.insert(cfg.sub_index) {
                        return Err(format!(
                            "Duplicate sub_index/subnet_index found: {}",
                            cfg.sub_index
                        ));
                    }
                }
                IPV6RaConfigSource::Pd(cfg) => {
                    if !depend_ifaces.insert(cfg.depend_iface.clone()) {
                        return Err(format!("Duplicate depend_iface found: {}", cfg.depend_iface));
                    }

                    if !sub_indices.insert(cfg.subnet_index) {
                        return Err(format!(
                            "Duplicate sub_index/subnet_index found: {}",
                            cfg.subnet_index
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ra.d.ts")]
pub struct RouterFlags {
    pub managed_address_config: bool, // 0b1000_0000
    pub other_config: bool,           // 0b0100_0000
    pub home_agent: bool,             // 0b0010_0000
    pub prf: u8,                      // 0b0001_1000 (Default Router Preference)
    pub nd_proxy: bool,               // 0b0000_0100
    pub reserved: u8,                 // 0b0000_0011
}

// 实现 From<u8>，用于从字节转换为结构体
impl From<u8> for RouterFlags {
    fn from(byte: u8) -> Self {
        Self {
            managed_address_config: (byte & 0b1000_0000) != 0,
            other_config: (byte & 0b0100_0000) != 0,
            home_agent: (byte & 0b0010_0000) != 0,
            prf: (byte & 0b0001_1000) >> 3,
            nd_proxy: (byte & 0b0000_0100) != 0,
            reserved: byte & 0b0000_0011,
        }
    }
}

// 实现 Into<u8>，用于将结构体转换回字节
impl Into<u8> for RouterFlags {
    fn into(self) -> u8 {
        (self.managed_address_config as u8) << 7
            | (self.other_config as u8) << 6
            | (self.home_agent as u8) << 5
            | (self.prf << 3)
            | (self.nd_proxy as u8) << 2
            | self.reserved
    }
}

fn ra_flag_default() -> RouterFlags {
    0xc0.into()
}

impl IPV6RAConfig {
    pub fn new(depend_iface: String) -> Self {
        let source = vec![IPV6RaConfigSource::Pd(IPv6RaPdConfig {
            depend_iface,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 300,
            prefix_len: 64,
            subnet_index: 1,
        })];
        Self {
            source,
            ra_flag: ra_flag_default(),
            ad_interval: 300,
        }
    }
}

impl LandscapeStore for IPV6RAServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}
