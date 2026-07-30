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
  assigned: {
    hostname: "Hostname",
    mac_addr: "MAC Address",
    mac_tip_1:
      "ARP scan results may include proxy ARP responses, which can cause duplicate IP entries with different MAC addresses.",
    assigned_ip: "Assigned IP",
    latest_request: "Latest Request Time",
    lease_left: "Remaining Lease Time (s)",
    expire_time: "Expiration Time",
    online_24h: "24h Online Status",
    online_24h_tip_1:
      "The last block indicates online status in the latest hour scan.",
    online_24h_tip_2:
      "Because scans are periodic, newly assigned IPs may still appear offline in the latest hour.",
    actions: "Actions",
    static_assigned: "Static Assignment",
    unknown: "Unknown",
  },
};
