export default {
  service: {
    title: "DHCPv4 Service Config",
    warning: "Disabling DHCP may prevent LAN hosts from accessing the router",
    server_ip: "DHCP Server IP",
    range_start: "Assigned IP Start (inclusive)",
    range_end: "Assigned IP End (exclusive)",
    save_success: "Saved successfully",
    save_failed: "Save failed",
  },
  lease_time: "Lease Time (seconds)",
  lease_time_tip: "Client must renew IP within this time. Default 86400 (24h)",
  custom_options: "Custom DHCP Options",
  invalid_ipv4_check:
    "Please enter valid IPv4 addresses and mask before saving",
  duplicate_option_check:
    "Duplicate option types found. Please fix before saving",
  invalid_option_check: "Invalid DHCP option value. Please fix before saving",
  option_dnr: {
    use_local: "Use Local DoH",
    use_custom: "Custom DoH",
    local_alert:
      "Automatically generate DHCP Option 162 using the local API/DoH certificate domain, current DHCP service address, DoH port and DoH path.",
    custom_alert:
      "Empty fields fall back to local DoH settings; domain must be the exact hostname covered by the certificate. Wildcard domains are not automatically converted to bare domains.",
    domain_label: "DoH Domain",
    ipv4_label: "IPv4 Address",
    port_label: "Port",
    port_placeholder: "Defaults to local DoH port",
    path_label: "DoH Path",
    path_placeholder: "Defaults to local DoH path, e.g. /dns-query",
  },
};
