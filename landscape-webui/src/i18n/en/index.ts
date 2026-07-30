import common from "./common";
import routes from "./routes";

import aboutUi from "./about/index";
import certUi from "./cert/index";
import certErr from "./cert/error";
import ddnsUi from "./ddns/index";
import ddnsErr from "./ddns/error";
import dnsProviderUi from "./dns_provider/index";
import dnsProviderErr from "./dns_provider/error";
import configUi from "./config/index";
import deviceUi from "./device/index";
import deviceErr from "./device/error";
import dhcpV4Ui from "./dhcp_v4/index";
import dhcpV4Err from "./dhcp_v4/error";
import dhcpV6Ui from "./dhcp_v6/index";
import dnsUi from "./dns/index";
import dnsErr from "./dns/error";
import dockerUi from "./docker/index";
import dockerErr from "./docker/error";
import firewallUi from "./firewall/index";
import firewallErr from "./firewall/error";
import flowUi from "./flow/index";
import flowErr from "./flow/error";
import gatewayUi from "./gateway/index";
import gatewayErr from "./gateway/error";
import geoUi from "./geo/index";
import geoErr from "./geo/error";
import interfaceUi from "./interface/index";
import lanIpv6Ui from "./lan_ipv6/index";
import lanIpv6Err from "./lan_ipv6/error";
import dnsMetrics from "./metrics/dns";
import connectMetrics from "./metrics/connect";
import natUi from "./nat/index";
import natErr from "./nat/error";
import networkUi from "./network/index";
import notFoundUi from "./not_found/index";
import pppoeUi from "./pppoe/index";
import sysinfoUi from "./sysinfo/index";
import terminalUi from "./terminal/index";
import topologyUi from "./topology/index";
import wifiUi from "./wifi/index";

import authErr from "./error/auth";
import configErr from "./error/config";
import serviceErr from "./error/service";
import commonErr from "./error/common";

export default {
  common,
  routes,
  about: aboutUi,
  cert: certUi,
  ddns: ddnsUi,
  dns_provider: dnsProviderUi,
  config: configUi,
  device: deviceUi,
  dhcp_v4: dhcpV4Ui,
  dhcp_v6: dhcpV6Ui,
  dns: dnsUi,
  docker: dockerUi,
  firewall: firewallUi,
  flow: flowUi,
  gateway: gatewayUi,
  geo: geoUi,
  interface: interfaceUi,
  lan_ipv6: lanIpv6Ui,
  nat: natUi,
  network: networkUi,
  not_found: notFoundUi,
  pppoe: pppoeUi,
  sysinfo: sysinfoUi,
  terminal: terminalUi,
  topology: topologyUi,
  wifi: wifiUi,
  // "metric" is a cross-cutting concern for metrics display pages.
  // DNS metrics here display query analytics, not DNS feature configuration.
  metric: {
    dns: dnsMetrics,
    connect: connectMetrics,
  },
  errors: {
    ...certErr,
    ...ddnsErr,
    ...dnsProviderErr,
    ...deviceErr,
    ...dhcpV4Err,
    ...dnsErr,
    ...dockerErr,
    ...firewallErr,
    ...flowErr,
    ...gatewayErr,
    ...geoErr,
    ...lanIpv6Err,
    ...natErr,
    ...authErr,
    ...configErr,
    ...serviceErr,
    ...commonErr,
  },
};
