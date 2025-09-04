use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use ts_rs::TS;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::dns::upstream::DnsUpstreamMode;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
pub struct DnsUpstreamConfig {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    pub id: Uuid,

    pub remark: String,

    pub mode: DnsUpstreamMode,

    pub ips: Vec<IpAddr>,

    pub port: Option<u16>,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
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
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            port: Some(53),
            update_at: get_f64_timestamp(),
        }
    }
}
