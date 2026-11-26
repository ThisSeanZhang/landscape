export default {
  connect_metric_title: "Connection metrics",
  conn_retention_mins: "Connection Metric Settings",
  connect_second_window_mins: "Second Window (Mins)",
  connect_second_window_mins_desc:
    "In-memory retention window for second-level connection charts",
  conn_retention_minute_days: "Aggregated Data (Minute)",
  conn_retention_minute_days_desc:
    "Retention period for minute aggregated connection metrics in days",
  conn_retention_hour_days: "Aggregated Data (Hour)",
  conn_retention_hour_days_desc:
    "Retention period for hourly aggregated connection metrics in days",
  conn_retention_day_days: "Aggregated Data (Day)",
  conn_retention_day_days_desc:
    "Retention period for daily aggregated connection metrics in days",

  conn_detail_settings: "Connection Detail Settings",
  conn_summary_retention_days: "Detail Retention (Days)",
  conn_summary_retention_days_desc:
    "Retention period for per-connection detail summary rows in days",
  conn_summary_max_rows: "Detail Row Cap",
  conn_summary_max_rows_desc:
    "Maximum number of detail summary rows kept in the conn_summaries table (0 = unlimited)",
  connect_db_max_mb: "Connection Database Size Cap (MB)",
  connect_db_max_mb_desc:
    "Maximum size of the connection metrics database (0 = unlimited, min 16MB when non-zero); cleanup starts ahead of the cap to keep write headroom",
  write_batch_size: "Write Batch Size",
  write_batch_size_desc: "Maximum record count for metrics flush to disk",
};
