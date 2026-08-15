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

    pub remark: String,

    pub mode: DnsUpstreamMode,

    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,

    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub port: Option<u16>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub enable_ip_validation: Option<bool>,

    /// Source-address binding for connections to this upstream (optional).
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub bind_config: DnsBindConfig,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
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
            remark: "Landscape Router Default DNS Upstream".to_string(),
            mode: DnsUpstreamMode::Plaintext,
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))],
            enable_ip_validation: None,
            port: Some(53),
            bind_config: DnsBindConfig::default(),
            update_at: get_f64_timestamp(),
        }
    }
}
