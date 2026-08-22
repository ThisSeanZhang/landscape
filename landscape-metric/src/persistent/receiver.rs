use landscape_common::{
    config::MetricRuntimeConfig,
    metric::{connect::ConnectMetric, dns::DnsMetric},
};
use tokio::sync::mpsc;

use super::batch::{ConnectMetricBatch, DnsMetricBatch};

pub(crate) const QUEUE_CAPACITY: usize = 1024;

pub(crate) type ConnectInputQueue = (mpsc::Sender<ConnectMetric>, mpsc::Receiver<ConnectMetric>);
pub(crate) type ConnectWriteQueue =
    (mpsc::Sender<ConnectMetricBatch>, mpsc::Receiver<ConnectMetricBatch>);
pub(crate) type DnsInputQueue = (mpsc::Sender<DnsMetric>, mpsc::Receiver<DnsMetric>);
pub(crate) type DnsWriteQueue = (mpsc::Sender<DnsMetricBatch>, mpsc::Receiver<DnsMetricBatch>);

#[allow(dead_code)]
pub(crate) fn connect_input_queue() -> ConnectInputQueue {
    mpsc::channel(QUEUE_CAPACITY)
}

#[allow(dead_code)]
pub(crate) fn connect_write_queue() -> ConnectWriteQueue {
    mpsc::channel(QUEUE_CAPACITY)
}

#[allow(dead_code)]
pub(crate) fn dns_input_queue() -> DnsInputQueue {
    mpsc::channel(QUEUE_CAPACITY)
}

#[allow(dead_code)]
pub(crate) fn dns_write_queue() -> DnsWriteQueue {
    mpsc::channel(QUEUE_CAPACITY)
}

#[allow(dead_code)]
pub(crate) async fn run_connect_receiver(
    _input_rx: mpsc::Receiver<ConnectMetric>,
    _write_tx: mpsc::Sender<ConnectMetricBatch>,
    _config: MetricRuntimeConfig,
) -> Result<(), String> {
    todo!("collect Connect metrics and flush batches by count or interval")
}

#[allow(dead_code)]
pub(crate) async fn run_dns_receiver(
    _input_rx: mpsc::Receiver<DnsMetric>,
    _write_tx: mpsc::Sender<DnsMetricBatch>,
    _config: MetricRuntimeConfig,
) -> Result<(), String> {
    todo!("collect DNS metrics and flush batches by count or interval")
}
