export default {
  title: "Interface IPv4 Configuration Mode",
  mode_none: "None",
  mode_static: "Static IP",
  mode_pppoe_native: "PPPoE (Native)",
  mode_dhcp_client: "DHCP Client",
  static_ip: "Static IP",
  set_default_route: "Set default route",
  yes: "Yes",
  no: "No",
  route_ip: "Route IP",
  username: "Username",
  password: "Password",
  mtu: "MTU (Negotiation only, requires additional MSS clamping)",
  ac_name:
    "Requested AC name (leave empty unless needed, otherwise dialing may fail)",
  ac_name_tip:
    "When set, connection is limited to servers with matching AC name",
  dhcp_warn:
    "If firewall is enabled on this interface, configure rules to allow port 68",
  dhcp_hostname: "Hostname used in DHCP request",
  update: "Update",
  change_zone_title: "Change Interface Zone",
  change_zone_warning_1:
    "Changing zone will reset all services running on this interface",
  change_zone_warning_2:
    "It is recommended to set the IP configuration method in `/etc/network/interfaces` to manual",
  zone_undefined: "Undefined",
  console_parse_bitmask_failed: "Failed to parse bitmask:",
  console_get_config_failed: "Failed to get config:",
  console_save_config_failed: "Failed to save config:",
};
