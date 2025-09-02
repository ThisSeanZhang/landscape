use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use ts_rs::TS;
use uuid::Uuid;

use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;
use crate::{
    config::{
        dns::{DomainConfig, RuleSource},
        FlowId,
    },
    database::repository::LandscapeDBStore,
};

/// 用于定义 DNS 重定向的单元配置
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns_redirect.d.ts")]
pub struct DNSRedirectRule {
    #[serde(default = "gen_database_uuid")]
    #[ts(as = "Option<_>", optional)]
    pub id: Uuid,

    pub remark: String,

    pub enable: bool,

    pub match_rules: Vec<RuleSource>,

    pub result_info: Vec<IpAddr>,

    pub apply_flows: Vec<FlowId>,

    #[serde(default = "get_f64_timestamp")]
    #[ts(as = "Option<_>", optional)]
    pub update_at: f64,
}

impl LandscapeDBStore<Uuid> for DNSRedirectRule {
    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Default, Debug)]
pub struct DNSRedirectRuntimeRule {
    pub id: Uuid,
    pub match_rules: Vec<DomainConfig>,
    pub result_info: Vec<IpAddr>,
}
