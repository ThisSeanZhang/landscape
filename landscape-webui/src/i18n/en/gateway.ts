export default {
  edit_title: "Gateway Rule",
  name: "Rule Name",
  name_required: "Rule name is required",
  enabled: "Enabled",
  match_type: "Match Type",
  type_host: "Host Match",
  type_path_prefix: "Path Prefix",
  type_sni_proxy: "SNI Proxy",
  domains: "Domains",
  domains_required: "At least one domain is required",
  domain_placeholder: "Enter domain, e.g. example.com or *.example.com",
  domain_invalid: "Invalid domain format",
  path_prefix: "Path Prefix",
  path_prefix_required: "Path prefix is required",
  path_prefix_placeholder: "Enter path prefix, e.g. /api",

  // Upstream
  upstream: "Upstream",
  targets: "Targets",
  target_address: "Address",
  target_port: "Port",
  target_weight: "Weight",
  target_tls: "TLS",
  add_target: "Add Target",
  target_address_required: "Address is required",
  target_required: "At least one upstream target is required",

  // Load balance
  load_balance: "Load Balance",
  lb_round_robin: "Round Robin",
  lb_random: "Random",
  lb_consistent: "Consistent Hash",

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
  https_port: "HTTPS Port",
  rule_count: "Rule Count",

  // Card
  no_rules: "No gateway rules",
  add_domain: "Add Domain",
};
