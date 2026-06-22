use nat::NatEvent;
use serde::{Deserialize, Serialize};

use crate::metric::connect::ConnectMetric;
use crate::metric::dns::DnsMetric;

pub mod dns;
pub mod hub;
pub mod nat;
pub mod route;

#[derive(Debug, Serialize, Deserialize)]
pub enum LandscapeEvent {
    NAT(NatEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectMessage {
    Metric(ConnectMetric),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DnsMetricMessage {
    Metric(DnsMetric),
}
