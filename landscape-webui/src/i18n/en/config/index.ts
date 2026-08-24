export default {
  directory: "Config Directory",
  ui_title: "System Preference",
  dns_title: "Global DNS Config",
  lan_hostname_title: "LAN Hostname Config",
  metric_title: "Metric Monitoring Config",
  backup_title: "Backup & Export",

  save_ui: "Save Settings",
  save_dns: "Save DNS Config",
  save_lan_hostname: "Save LAN Hostname Config",
  save_metric: "Save Metric Config",

  lan_hostname_enable: "Enable LAN Hostnames",
  lan_suffix: "LAN Domain Suffix",
  lan_suffix_placeholder: "For example, lan or home.arpa",
  lan_suffix_desc:
    "Used for LAN hostname resolution and PTR records. Multi-label domains are supported; internationalized text is converted to Punycode. Leave empty to use the default suffix: lan.",

  metric_mode: "Metric Mode",
  metric_mode_desc:
    "Disable metrics entirely, keep realtime data in memory only, or enable DuckDB persistence",
  metric_mode_off: "Off (OFF)",
  metric_mode_memory: "Memory Only (MEM)",
  metric_mode_duckdb: "Persistent (DB)",

  language: "Language",
  theme: "Theme",
  theme_placeholder: "Light mode is under development",
  timezone: "System Timezone",
  timezone_placeholder: "Select or search, e.g.: Asia/Shanghai",

  cache_capacity: "Cache Capacity",
  cache_capacity_desc: "Maximum records allowed in DNS cache",
  cache_ttl: "Cache TTL (s)",
  cache_ttl_desc: "Maximum retention time for DNS cache records",
  cache_negative_ttl: "Negative Cache TTL (s)",
  cache_negative_ttl_desc:
    "Retention time for negative (NXDOMAIN/NODATA) DNS records",

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
    "Maximum number of detail summary rows kept per connection (0 = unlimited)",
  dns_retention_days: "DNS Retention (Days)",
  dns_retention_days_desc:
    "Retention period for DNS query logs and metrics in days",

  performance_settings: "Performance & Storage Settings",
  write_batch_size: "Write Batch Size",
  write_batch_size_desc: "Maximum record count for metrics flush to disk",
  write_flush_interval: "Commit Interval (s)",
  write_flush_interval_desc: "Maximum seconds before forcing a database commit",
  db_max_memory: "DB Max Memory (MB)",
  db_max_memory_desc: "Maximum memory allowed for DuckDB (metrics storage)",
  db_max_threads: "DB Max Threads",
  db_max_threads_desc: "Maximum background threads for database operations",

  maintenance_settings: "Cleanup Settings",
  cleanup_interval: "Cleanup Interval (s)",
  cleanup_interval_desc: "Interval between history cleanup tasks",
  cleanup_budget: "Cleanup Budget (ms)",
  cleanup_budget_desc: "Maximum milliseconds allowed per cleanup task",
  cleanup_slice_window: "Cleanup Slice Window (s)",
  cleanup_slice_window_desc:
    "Time granularity for each cleanup transaction slice",

  backup_desc:
    "You can export all current router configurations (including DNS, firewall, network interfaces, etc.) as an init file for quick recovery or migration.",
  export_init: "Export all current configurations as Init file",
  import_init_desc:
    "Upload an init file to validate its version first. When Upload only is disabled, the file is saved as landscape_init.toml for the next initialization.",
  select_init_file: "Select Init File",
  upload_only: "Upload only and validate",
  import_init: "Import Init File",
  import_file_required: "Please select an init file",
  import_validate_success:
    "Init file validated successfully, version: {version}",
  import_install_success:
    "Init file saved for the next initialization, version: {version}. Initialization lock has been handled.",
  import_install_warning:
    "Disabling upload only overwrites landscape_init.toml in the config directory and removes the initialization lock. The next restart will initialize from this init file.",

  // Change password
  password_title: "Change Password",
  current_password: "Current Password",
  current_password_placeholder: "Enter current password",
  new_password: "New Password",
  new_password_placeholder: "Min 8 chars, with uppercase, lowercase and digit",
  confirm_password: "Confirm New Password",
  confirm_password_placeholder: "Re-enter new password",
  change_password: "Change Password",
  password_change_success:
    "Password changed successfully. Please log in again.",
  password_mismatch: "New passwords do not match",
  password_same_as_old: "New password cannot be the same as current password",
  password_min_length: "Password must be at least 8 characters",
  password_need_lowercase: "Password must contain a lowercase letter",
  password_need_uppercase: "Password must contain an uppercase letter",
  password_need_digit: "Password must contain a digit",
  current_password_required: "Please enter current password",

  load_failed: "Failed to load configuration",
  save_success: "Save successful",
  save_failed: "Save failed",
  conflict: "Configuration conflict, please refresh and try again",

  chinese_simplified: "Simplified Chinese",
  english: "English",
  dark_mode: "Dark Mode",
  light_mode: "Light Mode",
  welcome: "Welcome, {username}",
  console_download_failed: "Failed to download config",
};
