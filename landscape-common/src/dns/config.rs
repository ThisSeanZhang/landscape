use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dns::upstream::DnsUpstreamMode;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DnsUpstreamConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,

    pub remark: String,

    pub mode: DnsUpstreamMode,

    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>))]
    pub ips: Vec<IpAddr>,

    pub port: Option<u16>,

    #[serde(default)]
    pub enable_ip_validation: Option<bool>,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for DnsUpstreamConfig {
    fn get_id(&self) -> Uuid {
        self.id
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
            update_at: get_f64_timestamp(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DnsBindConfig {
    /// 绑定地址 v4 (可选)
    #[ts(optional)]
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr4: Option<Ipv4Addr>,
    /// 绑定地址 v6 (可选)
    #[ts(optional)]
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr6: Option<Ipv6Addr>,
}
