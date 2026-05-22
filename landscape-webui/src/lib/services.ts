import { NetDev, WLANTypeTag } from "./dev";
import { ZoneType } from "./service_ipconfig";

export type ServiceStatus =
  | { t: "staring" }
  | { t: "running" }
  | { t: "stopping" }
  | { t: "stop" }
  | { t: "failed" };

export enum ServiceStatusType {
  Staring = "staring",
  Running = "running",
  Stopping = "stopping",
  Stop = "stop",
  Failed = "failed",
}

export function get_service_status_color(
  status: ServiceStatus | undefined,
  themeVars: any,
) {
  if (!status) return themeVars.textColor3;

  switch (status.t) {
    case ServiceStatusType.Running:
      return themeVars.successColor;
    case ServiceStatusType.Staring:
    case ServiceStatusType.Stopping:
      return themeVars.warningColor;
    case ServiceStatusType.Failed:
      return themeVars.errorColor;
    case ServiceStatusType.Stop:
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
    case ServiceStatusType.Staring:
      return t("common.starting");
    case ServiceStatusType.Running:
      return t("common.running");
    case ServiceStatusType.Stopping:
      return t("common.stopping");
    case ServiceStatusType.Failed:
      return t("common.failed");
    case ServiceStatusType.Stop:
    default:
      return t("common.stopped");
  }
}

export function get_service_status_tag_type(status: ServiceStatus | undefined) {
  if (!status) {
    return "default";
  }

  switch (status.t) {
    case ServiceStatusType.Running:
      return "success";
    case ServiceStatusType.Staring:
    case ServiceStatusType.Stopping:
      return "warning";
    case ServiceStatusType.Failed:
      return "error";
    case ServiceStatusType.Stop:
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

    this.route_lan = false;
    this.route_wan = false;

    if (dev.wifi_info !== undefined) {
      if (dev.wifi_info.wifi_type.t == WLANTypeTag.Station) {
        this.station = true;
      } else if (dev.wifi_info.wifi_type.t == WLANTypeTag.Ap) {
        // WiFi AP mode only allowed in LAN or Undefined zone, not WAN
        if (dev.zone_type !== ZoneType.Wan) {
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
      this.route_wan = true;
    } else if (dev.name === "docker0") {
      this.zone_type = false;
      this.ip_config = false;
      this.lan_ipv6 = true;
    } else if (dev.zone_type === ZoneType.Lan) {
      this.dhcp_v4 = true;
      this.ip_config = false;
      this.lan_ipv6 = true;
      this.route_lan = true;
    } else if (dev.zone_type === ZoneType.Wan) {
      this.pppd = true;
      this.ip_config = true;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
      this.mss_clamp = true;
      this.route_wan = true;
    }
  }
}
