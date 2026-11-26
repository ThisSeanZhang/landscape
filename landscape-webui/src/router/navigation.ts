import type { Component } from "vue";
import {
  Settings,
  CicsSystemGroup,
  ModelBuilder,
  ChartCombo,
  ServerDns,
  Devices,
  Dashboard,
  Certificate,
  Gateway,
} from "@vicons/carbon";
import { Wall } from "@vicons/tabler";
import { Docker } from "@vicons/fa";
import { BookGlobe20Regular } from "@vicons/fluent";

export interface NavigationItem {
  name: string;
  icon?: Component;
  children?: NavigationItem[];
  hideWhenUnavailable?: boolean;
}

export const navigation: NavigationItem[] = [
  {
    name: "routes.dashboard",
    icon: CicsSystemGroup,
  },
  {
    name: "routes.flow",
    icon: ModelBuilder,
  },
  {
    name: "routes.mac-binding",
    icon: Devices,
  },
  {
    name: "routes.network-status",
    icon: Dashboard,
    children: [
      { name: "routes.lan-devices" },
      { name: "routes.routes" },
      { name: "routes.ipv6-pd" },
    ],
  },
  {
    name: "routes.firewall-nat",
    icon: Wall,
    children: [
      { name: "routes.firewall" },
      { name: "routes.nat-v4" },
      { name: "routes.nat-v6" },
    ],
  },
  {
    name: "routes.dns",
    icon: ServerDns,
    children: [
      { name: "routes.dns-upstream" },
      { name: "routes.dns-redirect" },
    ],
  },
  {
    name: "routes.geo",
    icon: BookGlobe20Regular,
    children: [{ name: "routes.geo-domain" }, { name: "routes.geo-ip" }],
  },
  {
    name: "routes.domains",
    icon: Certificate,
    children: [
      { name: "routes.dns-provider-profiles" },
      { name: "routes.ddns" },
      { name: "routes.cert-accounts" },
      { name: "routes.certs" },
    ],
  },
  {
    name: "routes.gateway",
    icon: Gateway,
  },
  {
    name: "routes.docker",
    icon: Docker,
  },
  {
    name: "routes.metric-group",
    icon: ChartCombo,
    children: [
      { name: "routes.dns-metric" },
      { name: "routes.self-monitor-memory", hideWhenUnavailable: true },
      { name: "routes.connect-live" },
      { name: "routes.connect-iface" },
      { name: "routes.connect-src" },
      { name: "routes.connect-dst" },
      { name: "routes.connect-history" },
    ],
  },
  {
    name: "routes.config",
    icon: Settings,
  },
];
