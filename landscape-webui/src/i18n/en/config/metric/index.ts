import connect from "./connect";
import dns from "./dns";

export default {
  metric_title: "Metric Monitoring Config",
  save_metric: "Save Metric Config",
  metric_enabled: "Enable collection",
  metric_backend: "Storage backend",

  metric_mode: "Metric Mode",
  metric_mode_desc:
    "Disable metrics entirely, keep realtime data in memory only, or enable persistent storage",
  metric_mode_off: "Off (OFF)",
  metric_mode_memory: "Memory Only (MEM)",
  metric_mode_persistent: "Persistent (SQLite)",

  db_cap_min_hint: "Size cap must be 0 (unlimited) or at least 16MB",
  performance_settings: "Performance & Storage Settings",
  write_flush_interval: "Commit Interval (s)",
  write_flush_interval_desc:
    "Maximum seconds before forcing a database commit; DNS logs are flushed every ≤15s regardless",

  maintenance_settings: "Cleanup Settings",
  cleanup_interval: "Cleanup Interval (s)",
  cleanup_interval_desc: "Interval between history cleanup tasks",
  cleanup_budget: "Cleanup Budget (s)",
  cleanup_budget_desc: "Maximum seconds allowed per cleanup task",
  cleanup_slice_window: "Cleanup Slice Window (s)",
  cleanup_slice_window_desc:
    "Time granularity for each cleanup transaction slice",

  ...connect,
  ...dns,
};
