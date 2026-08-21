use duckdb::{params, Connection};
use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone)]
pub struct CleanupStats {
    pub deleted_1m: usize,
    pub deleted_1h: usize,
    pub deleted_1d: usize,
    pub deleted_iface_5s: usize,
    pub budget_hit: bool,
    pub elapsed_ms: u128,
}

fn query_next_timestamp_before(
    conn: &Connection,
    table: &str,
    time_column: &str,
    lower_bound_inclusive: u64,
    cutoff_exclusive: u64,
) -> Option<u64> {
    let sql = format!(
        "SELECT MIN({time_column}) FROM {table} WHERE {time_column} >= ?1 AND {time_column} < ?2"
    );
    conn.query_row(&sql, params![lower_bound_inclusive as i64, cutoff_exclusive as i64], |row| {
        row.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
    .map(|ts| ts.max(0) as u64)
}

fn delete_table_in_slices(
    conn: &Connection,
    table: &str,
    time_column: &str,
    cutoff_exclusive: u64,
    slice_window_ms: u64,
    deadline: Instant,
) -> (usize, bool) {
    let mut deleted_total = 0usize;
    let mut cursor = query_next_timestamp_before(conn, table, time_column, 0, cutoff_exclusive);

    while let Some(slice_start) = cursor {
        if Instant::now() >= deadline {
            return (deleted_total, true);
        }

        let slice_end = (slice_start.saturating_add(slice_window_ms)).min(cutoff_exclusive);
        let sql = format!("DELETE FROM {table} WHERE {time_column} >= ?1 AND {time_column} < ?2");
        let deleted = conn
            .execute(&sql, params![slice_start as i64, slice_end as i64])
            .unwrap_or_else(|error| {
                tracing::error!("failed to delete slice from {}: {}", table, error);
                0
            });
        deleted_total += deleted;

        cursor = query_next_timestamp_before(conn, table, time_column, slice_end, cutoff_exclusive);
    }

    (deleted_total, false)
}

pub fn cleanup_old_cold_metrics_only(
    conn: &Connection,
    cutoff_1m: u64,
    cutoff_1h: u64,
    cutoff_1d: u64,
    cleanup_time_budget_ms: u64,
    cleanup_slice_window_secs: u64,
) -> CleanupStats {
    let start = Instant::now();
    let budget_ms = cleanup_time_budget_ms.max(1);
    let deadline = start + Duration::from_millis(budget_ms);
    let slice_window_ms = cleanup_slice_window_secs.max(1) * 1000;

    let mut stats = CleanupStats::default();

    let (deleted_iface_5s, budget_hit) = delete_table_in_slices(
        conn,
        "iface_metrics_5s",
        "report_time",
        cutoff_1m,
        slice_window_ms,
        deadline,
    );
    stats.deleted_iface_5s = deleted_iface_5s;
    stats.budget_hit = budget_hit;
    if stats.budget_hit {
        stats.elapsed_ms = start.elapsed().as_millis();
        return stats;
    }

    let (deleted_1m, budget_hit) = delete_table_in_slices(
        conn,
        "conn_metrics_1m",
        "report_time",
        cutoff_1m,
        slice_window_ms,
        deadline,
    );
    stats.deleted_1m = deleted_1m;
    stats.budget_hit = budget_hit;
    if stats.budget_hit {
        stats.elapsed_ms = start.elapsed().as_millis();
        return stats;
    }

    let (deleted_1h, budget_hit) = delete_table_in_slices(
        conn,
        "conn_metrics_1h",
        "report_time",
        cutoff_1h,
        slice_window_ms,
        deadline,
    );
    stats.deleted_1h = deleted_1h;
    stats.budget_hit = budget_hit;
    if stats.budget_hit {
        stats.elapsed_ms = start.elapsed().as_millis();
        return stats;
    }

    let (deleted_1d, budget_hit) = delete_table_in_slices(
        conn,
        "conn_metrics_1d",
        "report_time",
        cutoff_1d,
        slice_window_ms,
        deadline,
    );
    stats.deleted_1d = deleted_1d;
    stats.budget_hit = budget_hit;
    stats.elapsed_ms = start.elapsed().as_millis();
    stats
}
