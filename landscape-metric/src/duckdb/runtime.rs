use duckdb::DuckdbConnectionManager;
use landscape_common::concurrency::task_label;

use super::store::DuckMetricStore;

impl DuckMetricStore {
    pub(crate) fn get_cold_pool(&self) -> Option<r2d2::Pool<DuckdbConnectionManager>> {
        self.cold_pool.read().expect("metric cold pool poisoned").clone()
    }

    pub(crate) async fn run_cold_query_default<T, F>(&self, op: &'static str, f: F) -> T
    where
        T: Default + Send + 'static,
        F: FnOnce(r2d2::Pool<DuckdbConnectionManager>) -> T + Send + 'static,
    {
        let Some(pool) = self.get_cold_pool() else {
            return T::default();
        };

        let span = tracing::info_span!("task", task = task_label::task::METRIC_QUERY, op = op);
        tokio::task::spawn_blocking(move || span.in_scope(|| f(pool))).await.unwrap_or_default()
    }
}
