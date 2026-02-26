import dns from "./metric/dns";
import connect from "./metric/connect";
import sysinfo from "./sysinfo";
import config from "./config";
import error from "./error";
import errors from "./errors";
import enrolled_device from "./enrolled_device";
import flow from "./flow";
import nat from "./nat";
import dns_editor from "./dns_editor";
import firewall from "./firewall";
import icmp_ra from "./icmp_ra";
import misc from "./misc";
import geo_editor from "./geo_editor";
import ipconfig_editor from "./ipconfig_editor";
import dhcp_editor from "./dhcp_editor";
import pppd_editor from "./pppd_editor";

export default {
  docker_divider: "Docker 容器",
  topology_divider: "网络拓扑",
  metric: {
    dns,
    connect,
  },
  sysinfo,
  config,
  error,
  errors,
  enrolled_device,
  flow,
  nat,
  dns_editor,
  firewall,
  icmp_ra,
  misc,
  geo_editor,
  ipconfig_editor,
  dhcp_editor,
  pppd_editor,
  common: {
    private_mode: "隐私模式",
  },
  routes: {
    dashboard: "系统概览",
    status: "服务状态",
    dns: "DNS 相关",
    "dns-redirect": "DNS 重定向",
    "dns-upstream": "上游 DNS",
    nat: "静态 NAT",
    flow: "分流设置",
    topology: "网络拓扑",
    docker: "Docker 管理",
    firewall: "防火墙",
    geo: "地理数据库管理",
    "geo-domain": "地理域名",
    "geo-ip": "地理 IP",
    config: "系统配置",
    "metric-group": "指标监控",
    "connect-info": "连接信息",
    "connect-live": "活跃连接",
    "connect-history": "历史查询",
    "connect-src": "源 IP 统计",
    "connect-dst": "目的 IP 统计",
    "connect-history-src": "源 IP 历史",
    "connect-history-dst": "目的 IP 历史",
    "dns-metric": "DNS 指标",
    "ipv6-pd": "IPv6 PD",
    "dhcp-v4": "DHCPv4 服务",
    "ipv6-ra": "IPv6 RA",
    "mac-binding": "设备管理",
  },
};
