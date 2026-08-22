mod batch;
mod parquet;
mod receiver;
mod sqlite;
mod writer;

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct PersistentMetricStore;

#[allow(dead_code)]
impl PersistentMetricStore {
    pub(crate) fn new(
        _base_path: std::path::PathBuf,
        _config: landscape_common::config::MetricRuntimeConfig,
    ) -> Self {
        todo!("implement persistent metric store")
    }
}
