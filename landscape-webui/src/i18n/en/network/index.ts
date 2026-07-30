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
};
