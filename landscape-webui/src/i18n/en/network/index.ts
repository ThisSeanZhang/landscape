export default {
  iface_cpu_balance: {
    title: "Configure NIC Soft Load Balancing",
    intro:
      "Select CPU cores for network queue processing. Choosing multiple cores can distribute load and improve performance.",
    hint_prefix: "Tip:",
    hint_suffix: 'Click "Set to 0" below to restore defaults',
    tx_title: "Transmit Queue (XPS) Core Selection",
    rx_title: "Receive Queue (RPS) Core Selection",
    set_zero: "Set to 0",
    selected: "Selected",
    none: "None",
    bitmask: "Bitmask",
    loading_cpu: "Loading CPU information...",
    reset: "Reset Selection",
    cancel: "Cancel",
    save: "Save Configuration",
  },
  iface_risk_guard: {
    title: "Confirm action on current access interface",
    warning:
      "You are currently connected through this interface. This operation may immediately disconnect this management session.",
    current_iface: "Current access interface: {iface}",
    current_ip: "Current IP: {ip}",
    current_source: "Lookup source: {source}",
    current_hostname: "Hostname: {hostname}",
    input_label: "Type interface name {iface} to confirm action",
    input_placeholder: "Enter {iface}",
    input_hint:
      "The action is only enabled when the input exactly matches the interface name.",
    confirm_button: "Confirm and continue",
  },
  route_lan: {
    title: "LAN Route Forwarding Service",
    static_route_limit: "Static Routes (only one supported currently)",
    add_subnet: "Add reachable subnet",
    next_hop: "Next hop",
    subnet_range: "Subnet range",
  },
  route_wan: {
    title: "WAN Route Forwarding Service",
  },
  mss_clamp: {
    title: "Configure TCP MSS Clamping",
    clamp_value: "Clamp Value",
  },
  health_check: {
    title: "WAN Link Health Check",
    targets: "Probe Targets (IPv4)",
    targets_tooltip:
      "Up to 4 IPv4 targets. With gateway probing enabled, the gateway learned by the session is probed additionally each round.",
    target_placeholder: "e.g. 1.1.1.1",
    add_target: "Add Probe Target",
    probe_gateway: "Probe Default Gateway",
    probe_gateway_hint:
      "Additionally probe the gateway learned from the session (DHCP/PPPoE).",
    interval_secs: "Interval (s)",
    interval_tooltip:
      "Time between probe rounds. Range 1-65535 seconds, default 10.",
    timeout_ms: "Timeout (ms)",
    timeout_tooltip:
      "How long a single probe waits for a reply. Range 1-10000 ms, default 1000; must be shorter than the interval.",
    failure_threshold: "Failure Threshold",
    failure_threshold_tooltip:
      "Consecutive failed rounds before the link is marked unhealthy. Range 1-100, default 3.",
    recovery_threshold: "Recovery Threshold",
    recovery_threshold_tooltip:
      "Consecutive successful rounds required to mark an unhealthy link healthy again. Range 1-100, default 3; keep it no smaller than the failure threshold to avoid flapping.",
    reliability: "Min Targets Up per Round",
    reliability_tooltip:
      "Each round pings every enabled target (configured targets plus the gateway if enabled). A round counts as successful only when at least this many targets answer. Consecutive failed rounds up to the failure threshold mark the link unhealthy; recovery threshold consecutive successes restore it. Range 1-100, and must not exceed the total target count. Example: targets 1.1.1.1, 8.8.8.8 plus the gateway make 3; set to 2, a single dead target does not fail the round.",
    reliability_range: "Reliability must be between 1 and 100",
    invalid_target: "Probe targets must be valid IPv4 addresses",
    nothing_to_probe:
      "Nothing to probe: add at least one target or enable gateway probing",
    save_failed: "Save failed",
  },
};
