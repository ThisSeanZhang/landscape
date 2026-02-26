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
  common: {
    private_mode: "Private Mode",
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
