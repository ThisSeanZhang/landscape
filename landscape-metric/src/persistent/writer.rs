use tokio::sync::mpsc;

use super::{
    batch::{ConnectMetricBatch, DnsMetricBatch},
    parquet::ParquetWriter,
    sqlite::SqliteWriter,
};

#[allow(dead_code)]
pub(crate) async fn run_connect_writer(
    _batch_rx: mpsc::Receiver<ConnectMetricBatch>,
    _sqlite: SqliteWriter,
    _parquet: ParquetWriter,
) -> Result<(), String> {
    todo!("aggregate Connect batches and write SQLite and Parquet data")
}

#[allow(dead_code)]
pub(crate) async fn run_dns_writer(
    _batch_rx: mpsc::Receiver<DnsMetricBatch>,
    _sqlite: SqliteWriter,
    _parquet: ParquetWriter,
) -> Result<(), String> {
    todo!("aggregate DNS batches and write SQLite and Parquet data")
}
