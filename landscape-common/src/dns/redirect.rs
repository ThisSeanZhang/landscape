use std::net::IpAddr;

use crate::{
    config::{
        dns::{DomainConfig, RuleSource},
        FlowId,
    },
    database::repository::LandscapeDBStore,
    utils::time::get_f64_timestamp,
};
use landscape_macro::LandscapeRequestModel;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

/// 用于定义 DNS 重定向的单元配置
#[derive(LandscapeRequestModel, Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns_redirect.d.ts")]
pub struct DNSRedirectRule {
    #[skip]
    pub id: Uuid,

    pub remark: String,

    pub enable: bool,

    pub match_rules: Vec<RuleSource>,

    pub result_info: Vec<IpAddr>,

    pub apply_flows: Vec<FlowId>,

    #[skip(default = "get_f64_timestamp")]
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
