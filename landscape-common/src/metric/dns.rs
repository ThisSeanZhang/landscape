use arc_swap::ArcSwapOption;
use tokio::sync::mpsc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Record, RecordType};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;

pub use super::api::{DnsHistoryResponse, DnsLightweightSummaryResponse, DnsSummaryResponse};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum DnsOutcome {
    Local,    // 重定向有值
    Block,    // 重定向空值
    Hit,      // 命中缓存
    NxDomain, // 域名不存在
    Filter,   // 被过滤 (OnlyIPv4/OnlyIPv6)
    #[default]
    Normal, // 正常透传
    Error,    // 异常
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsMetric {
    pub flow_id: u32,
    pub domain: String,
    pub query_type: String,
    pub response_code: String,
    pub status: DnsOutcome,
    pub report_time: u64,
    pub duration_ms: u32,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub src_ip: IpAddr,
    pub answers: Vec<String>,
}

#[derive(Debug)]
pub struct DnsMetricEvent {
    pub flow_id: u32,
    pub domain: Arc<str>,
    pub query_type: RecordType,
    pub response_code: ResponseCode,
    pub status: DnsOutcome,
    pub report_time: u64,
    pub duration_ms: u32,
    pub src_ip: IpAddr,
    pub answers: Vec<Record>,
}

/// Stable, best-effort DNS metric ingress shared across engine generations.
/// Clones observe target changes without rebuilding DNS handlers.
#[derive(Clone, Default)]
pub struct DnsMetricReporter {
    sender: Arc<ArcSwapOption<mpsc::Sender<DnsMetricEvent>>>,
}

impl DnsMetricReporter {
    /// Called by the metric lifecycle owner when installing or stopping an engine.
    pub fn replace_sender(&self, sender: Option<mpsc::Sender<DnsMetricEvent>>) {
        self.sender.store(sender.filter(|sender| !sender.is_closed()).map(Arc::new));
    }

    /// Never waits or retries. Returns whether the event was queued, not persisted.
    /// Disabled/closed targets skip event construction entirely. Concurrent switches
    /// may drop an event that already selected the previous engine's channel.
    pub fn record_with(&self, event: impl FnOnce() -> DnsMetricEvent) -> bool {
        let Some(sender) = self.sender.load_full().filter(|sender| !sender.is_closed()) else {
            return false;
        };
        sender.try_send(event()).is_ok()
    }
}

impl DnsMetricEvent {
    pub fn into_metric(self) -> DnsMetric {
        DnsMetric {
            flow_id: self.flow_id,
            domain: self.domain.to_string(),
            query_type: self.query_type.to_string(),
            response_code: self.response_code.to_string(),
            status: self.status,
            report_time: self.report_time,
            duration_ms: self.duration_ms,
            src_ip: self.src_ip,
            answers: self.answers.iter().map(|r| r.to_string()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DnsSortKey {
    #[default]
    Time,
    Domain,
    Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct DnsHistoryQueryParams {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub start_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub end_time: Option<u64>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub limit: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub offset: Option<usize>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub domain: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub src_ip: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub query_type: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub status: Option<DnsOutcome>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub min_duration_ms: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub max_duration_ms: Option<u32>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_key: Option<DnsSortKey>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub sort_order: Option<crate::metric::connect::SortOrder>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
pub struct DnsSummaryQueryParams {
    pub start_time: u64,
    pub end_time: u64,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub flow_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsStatEntry {
    pub name: String,
    pub count: usize,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub value: Option<f64>,
}

#[cfg(test)]
mod reporter_tests {
    use super::*;

    fn event(flow_id: u32) -> DnsMetricEvent {
        DnsMetricEvent {
            flow_id,
            domain: "example.com".into(),
            query_type: RecordType::A,
            response_code: ResponseCode::NoError,
            status: DnsOutcome::Normal,
            report_time: 1,
            duration_ms: 1,
            src_ip: "127.0.0.1".parse().unwrap(),
            answers: vec![],
        }
    }

    #[tokio::test]
    async fn existing_clones_follow_replacements_without_forwarding_or_replay() {
        let owner = DnsMetricReporter::default();
        let dns = owner.clone();
        let (first_tx, mut first_rx) = mpsc::channel(1);
        owner.replace_sender(Some(first_tx));
        assert!(dns.record_with(|| event(1)));
        assert_eq!(first_rx.recv().await.unwrap().flow_id, 1);
        owner.replace_sender(None);
        assert!(!dns.record_with(|| panic!("disabled must skip event construction")));
        let (next_tx, mut next_rx) = mpsc::channel(1);
        owner.replace_sender(Some(next_tx));
        assert!(dns.record_with(|| event(2)));
        assert_eq!(next_rx.recv().await.unwrap().flow_id, 2);
        assert!(first_rx.recv().await.is_none());
        assert!(next_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn full_and_closed_channels_do_not_block() {
        let reporter = DnsMetricReporter::default();
        let (tx, mut rx) = mpsc::channel(1);
        reporter.replace_sender(Some(tx));
        assert!(reporter.record_with(|| event(1)));
        assert!(!reporter.record_with(|| event(2)));
        assert_eq!(rx.recv().await.unwrap().flow_id, 1);
        drop(rx);
        assert!(!reporter.record_with(|| panic!("closed must skip event construction")));
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        reporter.replace_sender(Some(closed_tx));
        assert!(!reporter.record_with(|| panic!("closed replacement must stay disabled")));
    }
}
