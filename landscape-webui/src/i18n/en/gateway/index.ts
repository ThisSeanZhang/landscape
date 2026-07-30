export default {
  runtime_title: "Gateway Runtime",
  edit_title: "Gateway Rule",
  name: "Rule Name",
  name_required: "Rule name is required",
  enabled: "Enabled",
  enabled_desc:
    "Controls whether the gateway process should be started after restart",
  match_type: "Match Type",
  type_host: "Host Match",
  type_sni_proxy: "SNI Proxy",
  type_legacy_path_prefix: "Legacy Path Prefix",
  domains: "Domains",
  domains_required: "At least one domain is required",
  domain_placeholder: "Enter domain, e.g. example.com or *.example.com",
  domain_invalid: "Invalid domain format",
  path_prefix: "Path Prefix",
  path_prefix_required: "Path prefix is required",
  path_prefix_placeholder: "Enter path prefix, e.g. /api",
  path_groups: "Path Groups",
  no_path_groups:
    "No path groups configured; requests fall back to the default upstream",
  add_path_group: "Add Path Group",
  path_group_editor: "Edit Path Group",
  default_upstream: "Default Upstream",
  rewrite_mode: "Path Forwarding",
  rewrite_preserve: "Preserve Path",
  rewrite_strip_prefix: "Strip Matched Prefix",
  legacy_read_only:
    "Legacy path-prefix rules are read-only; they can be viewed and deleted but not edited",

  // Upstream
  upstream: "Upstream",
  targets: "Targets",
  target_address: "Address",
  target_port: "Port",
  target_weight: "Weight",
  target_tls: "TLS",
  target_tls_tip: "Enable only when the upstream service listens over HTTPS.",
  target_skip_cert_verify: "Skip Cert",
  target_skip_cert_verify_tip:
    "When enabled, the gateway will not validate the upstream TLS certificate. Use it for self-signed certificates on a trusted internal network.",
  add_target: "Add Target",
  target_address_required: "Address is required",
  target_required: "At least one upstream target is required",

  // Load balance
  load_balance: "Load Balance",
  lb_round_robin: "Round Robin",
  lb_random: "Random",
  lb_consistent: "Consistent Hash",

  // Request headers
  client_ip_headers: "Client IP Forwarding",
  client_ip_standard: "Use Standard Proxy Headers",
  client_ip_disabled: "Disabled",
  request_headers: "Custom Request Headers",
  add_header: "Add Header",
  header_name: "Header Name",
  header_value: "Header Value",
  header_name_required: "Header name is required",
  header_mode: "Duplicate Header Handling",
  header_mode_set: "Set",
  header_mode_append: "Append",

  // Health check
  health_check: "Health Check",
  health_check_enable: "Enable Health Check",
  hc_interval: "Interval (s)",
  hc_timeout: "Timeout (s)",
  hc_healthy_threshold: "Healthy Threshold",
  hc_unhealthy_threshold: "Unhealthy Threshold",

  // Status
  status_title: "Gateway Status",
  status_running: "Running",
  status_stopped: "Stopped",
  http_port: "HTTP Port",
  http_port_desc: "Listening port for plaintext HTTP traffic",
  https_port: "HTTPS Port",
  https_port_desc: "Listening port for TLS traffic",
  rule_count: "Rule Count",
  save_runtime: "Save Runtime Config",
  save_and_restart: "Save & Restart",
  restart_hint:
    "Port and enable changes take effect after restart. Save & Restart applies the current form values immediately.",
  restart_success: "Gateway restarted successfully",
  restart_failed: "Failed to restart gateway",

  // Card
  no_rules: "No gateway rules",
  add_domain: "Add Domain",
};
