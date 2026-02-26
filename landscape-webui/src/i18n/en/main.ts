import dns from "./metric/dns";
import connect from "./metric/connect";
import sysinfo from "./sysinfo";
import config from "./config";
import error from "./error";
import errors from "./errors";
import lan_ipv6 from "./lan_ipv6";
import enrolled_device from "./enrolled_device";
import flow from "./flow";
import nat from "./nat";
import dns_editor from "./dns_editor";
import firewall from "./firewall";
import misc from "./misc";
import geo_editor from "./geo_editor";
import ipconfig_editor from "./ipconfig_editor";
import dhcp_editor from "./dhcp_editor";
import pppd_editor from "./pppd_editor";

export default {
  docker_divider: "Docker Containers",
  topology_divider: "Network topology",
  metric: {
    dns,
    connect,
  },
  sysinfo,
  config,
  error,
  errors,
  lan_ipv6,
  enrolled_device,
  flow,
  nat,
  dns_editor,
  firewall,
  misc,
  geo_editor,
  ipconfig_editor,
  dhcp_editor,
  pppd_editor,
  common: {
    private_mode: "Private Mode",
    create: "Create",
    edit: "Edit",
    delete: "Delete",
    confirm_delete: "Confirm deletion?",
    no_remark: "No remark",
    not_configured: "Not Configured",
    starting: "Starting",
    running: "Running",
    stopping: "Stopping",
    stopped: "Stopped",
    confirm_stop: "Confirm stop?",
    created_at: "Created At",
    create_bridge_device: "Create Bridge Device",
    add_bridge: "Add Bridge",
    refresh: "Refresh",
    force_refresh: "Force Refresh",
    force_refresh_confirm: "Force refresh? This will clear all keys and re-download.",
    force_refresh_confirm_long:
      "Force refresh? This will clear all keys and re-download. It may take some time.",
    domain_rule_source_config: "Domain Rule Source Config",
    ip_rule_source_config: "IP Rule Source Config",
    image: "Image",
    close_listener: "Stop Service",
    docker_image_list: "Docker Image List",
    pull_image: "Pull Image",
    pull_image_name_required: "Image name cannot be empty",
    port_mapping: "Port Mapping",
    ipv4_target: "IPv4 Target",
    ipv6_target: "IPv6 Target",
    updated_at: "Updated At",
    no_firewall_rules: "No blacklist rules",
    list_no_auto_refresh:
      "The list does not auto-refresh currently. IPs inactive for 30s will be marked as",
    refresh_interval_ms: "Refresh interval (ms):",
    confirm: "Confirm",
  },
  routes: {
    dashboard: "Dashboard",
    status: "Service Status",
    dns: "DNS Settings",
    "dns-redirect": "DNS Redirect",
    "dns-upstream": "Upstream DNS",
    nat: "Static NAT",
    flow: "Traffic Flow",
    topology: "Network Topology",
    docker: "Docker Management",
    firewall: "Firewall",
    geo: "Geo Database",
    "geo-domain": "Geo Domain",
    "geo-ip": "Geo IP",
    config: "System Config",
    "metric-group": "Metrics",
    "connect-info": "Connections",
    "connect-live": "Active Connections",
    "connect-history": "History Query",
    "connect-src": "Src IP Stats",
    "connect-dst": "Dst IP Stats",
    "connect-history-src": "Src IP History",
    "connect-history-dst": "Dst IP History",
    "dns-metric": "DNS Metrics",
    "ipv6-pd": "IPv6 PD",
    "dhcp-v4": "DHCPv4 Service",
    "ipv6-ra": "IPv6 RA",
    "mac-binding": "Devices",
  },
};
