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
};
