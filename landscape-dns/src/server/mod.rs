use std::sync::Arc;

use arc_swap::ArcSwapOption;
use landscape_common::metric::dns::DnsMetricEvent;
use tokio::sync::mpsc;

pub mod builder;
pub(crate) mod handler;
pub(crate) mod service;
pub(crate) mod snapshot;
pub(crate) mod traits;

pub use builder::EngineBuilder;
pub use service::{DnsServiceDeps, FlowRuntimeRefreshKind, LandscapeDnsServer};

pub(crate) type MetricSenderState = Arc<ArcSwapOption<mpsc::Sender<DnsMetricEvent>>>;
