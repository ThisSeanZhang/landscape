export default {
  "time.invalid_servers":
    "Enter at least one NTP server. Use a hostname or IP address, and enclose IPv6 addresses in brackets when specifying a port.",
  "self_monitor.invalid_retention":
    "Memory history retention must be at least one day.",
  "metric.sqlite_unavailable":
    "SQLite metric storage is unavailable in this build.",
  "metric.invalid_db_max_mb":
    "{field} must be 0 (unlimited) or between 16 and 1048576 MB, got {value}",
  "metric.invalid_cleanup_time_budget":
    "cleanup_time_budget_secs must be between 1 and 60 seconds, got {value}",
  "init_config.file_not_found": "Init file not found in upload",
  "init_config.export_serialization_failed":
    "Failed to serialize the exported configuration",
  "init_config.file_read_error": "Failed to read init file",
  "init_config.invalid": "Invalid init file: {reason}",
  "init_config.version_mismatch":
    "Init file version mismatch. File version: {file_version}, current version: {current_version}",
  "config.conflict":
    "Configuration has been modified. Please refresh and try again",
  "lan_hostname.invalid_suffix.invalid_idna":
    "LAN hostname suffix '{suffix}' is not a valid IDNA label",
  "lan_hostname.invalid_suffix.empty_label":
    "LAN hostname suffix '{suffix}' contains an empty DNS label",
  "lan_hostname.invalid_suffix.too_long":
    "LAN hostname suffix '{suffix}' exceeds DNS name or label length limits",
  "lan_hostname.invalid_suffix.invalid_hyphen":
    "LAN hostname suffix '{suffix}' cannot start or end with a hyphen",
  "lan_hostname.invalid_suffix.invalid_character":
    "LAN hostname suffix '{suffix}' may contain only letters, digits, and hyphens",
  "lan_hostname.invalid_suffix.reserved":
    "LAN hostname suffix '{suffix}' is reserved by the DNS resolver",
};
