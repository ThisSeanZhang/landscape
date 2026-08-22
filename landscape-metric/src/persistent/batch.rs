#![allow(dead_code)]

use landscape_common::metric::{connect::ConnectMetric, dns::DnsMetric};

#[derive(Debug, Default)]
pub(crate) struct ConnectMetricBatch {
    items: Vec<ConnectMetric>,
}

impl ConnectMetricBatch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, metric: ConnectMetric) {
        self.items.push(metric);
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn into_items(self) -> Vec<ConnectMetric> {
        self.items
    }
}

#[derive(Debug, Default)]
pub(crate) struct DnsMetricBatch {
    items: Vec<DnsMetric>,
}

impl DnsMetricBatch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, metric: DnsMetric) {
        self.items.push(metric);
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn into_items(self) -> Vec<DnsMetric> {
        self.items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::{
        connect::{ConnectKey, ConnectStatusType},
        dns::DnsOutcome,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn connect_metric() -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time: 1, cpu_id: 0 },
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 1,
            dst_port: 2,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: 1,
            trace_id: 1,
            gress: 0,
            ifindex: 1,
            report_time: 1,
            create_time_ms: 1,
            ingress_bytes: 1,
            ingress_packets: 1,
            egress_bytes: 1,
            egress_packets: 1,
            status: ConnectStatusType::Active,
        }
    }

    fn dns_metric() -> DnsMetric {
        DnsMetric {
            flow_id: 1,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: DnsOutcome::Normal,
            report_time: 1,
            duration_ms: 1,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        }
    }

    #[test]
    fn connect_batch_collects_and_transfers_items() {
        let mut batch = ConnectMetricBatch::new();
        assert!(batch.is_empty());

        batch.push(connect_metric());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());

        assert_eq!(batch.into_items().len(), 1);
    }

    #[test]
    fn dns_batch_collects_and_transfers_items() {
        let mut batch = DnsMetricBatch::new();
        assert!(batch.is_empty());

        batch.push(dns_metric());
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());

        assert_eq!(batch.into_items().len(), 1);
    }
}
