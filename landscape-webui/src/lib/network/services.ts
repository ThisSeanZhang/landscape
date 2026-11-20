import type { ServiceStatus } from "@landscape-router/types/api/schemas";
import { NetDev } from "./dev";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";

export function get_service_status_color(
  status: ServiceStatus | undefined,
  themeVars: any,
) {
  if (!status) return themeVars.textColor3;

  switch (status.t) {
    case "running":
      return themeVars.successColor;
    case "staring":
    case "stopping":
      return themeVars.warningColor;
    case "failed":
      return themeVars.errorColor;
    case "stop":
    case "disabled":
    default:
      return themeVars.textColor3;
  }
}

export function get_service_status_label(
  status: ServiceStatus | undefined,
  t: (key: string) => string,
) {
  if (!status) {
    return t("common.not_configured");
  }

  switch (status.t) {
    case "staring":
      return t("common.starting");
    case "running":
      return t("common.running");
    case "stopping":
      return t("common.stopping");
    case "failed":
      return t("common.failed");
    case "disabled":
      return t("common.disabled");
    case "stop":
    default:
      return t("common.stopped");
  }
}

export function get_service_status_tag_type(status: ServiceStatus | undefined) {
  if (!status) {
    return "default";
  }

  switch (status.t) {
    case "running":
      return "success";
    case "staring":
    case "stopping":
      return "warning";
    case "failed":
      return "error";
    case "stop":
    case "disabled":
    default:
      return "default";
  }
}

export class ServiceExhibitSwitch {
  carrier: boolean;
  enable_in_boot: boolean;
  zone_type: boolean;
  pppd: boolean;
  ip_config: boolean;
  nat_config: boolean;
  mark_config: boolean;
  ipv6pd: boolean;
  lan_ipv6: boolean;
  firewall: boolean;
  wifi: boolean;
  station: boolean;
  dhcp_v4: boolean;
  mss_clamp: boolean;
  health_check: boolean;
  route_lan: boolean;
  route_wan: boolean;

  constructor(dev: NetDev) {
    this.carrier = true;
    this.enable_in_boot = true;
    this.zone_type = true;
    this.pppd = false;
    this.ip_config = false;
    this.nat_config = false;
    this.mark_config = false;
    this.ipv6pd = false;
    this.lan_ipv6 = false;
    this.firewall = false;
    this.wifi = false;
    this.station = false;
    this.dhcp_v4 = false;
    this.mss_clamp = false;
    this.health_check = false;

    this.route_lan = false;
    this.route_wan = false;

    if (dev.wifi_info !== undefined) {
      if (dev.wifi_info.wifi_type.t == "Station") {
        this.station = true;
      } else if (dev.wifi_info.wifi_type.t == "Ap") {
        // WiFi AP mode only allowed in LAN or Undefined zone, not WAN
        if (dev.zone_type !== IfaceZoneType.wan) {
          this.wifi = true;
        }
      }
    }
    if (dev.controller_id != undefined) {
      this.zone_type = false;
      this.enable_in_boot = false;
      this.ip_config = false;
    }

    if (dev.peer_link_id != undefined) {
      this.enable_in_boot = false;
      this.ip_config = false;
    }

    if (dev.dev_type === "ppp") {
      this.enable_in_boot = false;
      this.ip_config = false;
      this.zone_type = false;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
      this.mss_clamp = true;
      this.health_check = true;
      this.route_wan = true;
    } else if (dev.name === "docker0") {
      this.zone_type = false;
      this.ip_config = false;
      this.lan_ipv6 = true;
    } else if (dev.zone_type === IfaceZoneType.lan) {
      this.dhcp_v4 = true;
      this.ip_config = false;
      this.lan_ipv6 = true;
      this.route_lan = true;
    } else if (dev.zone_type === IfaceZoneType.wan) {
      this.pppd = true;
      this.ip_config = true;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
      this.mss_clamp = true;
      this.health_check = true;
      this.route_wan = true;
    }
  }
}
