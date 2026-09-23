import { NetDev, WLANTypeTag } from "./dev";
import { IfaceZoneType } from "@landscape-router/types/api/schemas";

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
  lan_ipv6: boolean;
  wifi: boolean;
  station: boolean;
  dhcp_v4: boolean;
  route_lan: boolean;
  route_wan: boolean;

  constructor(dev: NetDev) {
    this.carrier = true;
    this.enable_in_boot = true;
    this.zone_type = true;
    this.lan_ipv6 = false;
    this.wifi = false;
    this.station = false;
    this.dhcp_v4 = false;
    this.route_lan = false;
    this.route_wan = false;

    if (dev.wifi_info !== undefined) {
      if (dev.wifi_info.wifi_type.t == WLANTypeTag.Station) {
        this.station = true;
      } else if (dev.wifi_info.wifi_type.t == WLANTypeTag.Ap) {
        // WiFi AP mode only allowed in LAN or Undefined zone, not WAN
        if (dev.zone_type !== IfaceZoneType.wan) {
          this.wifi = true;
        }
      }
    }
    if (dev.controller_id != undefined) {
      this.zone_type = false;
      this.enable_in_boot = false;
    }

    if (dev.peer_link_id != undefined) {
      this.enable_in_boot = false;
    }

    if (dev.dev_type === "ppp") {
      this.enable_in_boot = false;
      this.zone_type = false;
    } else if (dev.name === "docker0") {
      this.zone_type = false;
      this.lan_ipv6 = true;
    } else if (dev.zone_type === IfaceZoneType.lan) {
      this.dhcp_v4 = true;
      this.lan_ipv6 = true;
      this.route_lan = true;
    } else if (dev.zone_type === IfaceZoneType.wan) {
      this.route_wan = true;
    }
  }
}
