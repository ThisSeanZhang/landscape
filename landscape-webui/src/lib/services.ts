import type {
  LandscapeInterface,
  LandscapeWifiInterface,
  NetworkIfaceConfig,
} from "landscape-types/api/schemas";
import { NetDev, WLANTypeTag } from "./dev";
import { ZoneType } from "./service_ipconfig";

export type ServiceStatus =
  | { t: "staring" }
  | { t: "running" }
  | { t: "stopping" }
  | { t: "stop" };

export enum ServiceStatusType {
  Staring = "staring",
  Running = "running",
  Stopping = "stopping",
  Stop = "stop",
}

export function get_service_status_color(
  status: ServiceStatus | undefined,
  themeVars: any,
) {
  if (!status) return "";
  return status.t === ServiceStatusType.Running ? themeVars.successColor : "";
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
  icmpv6ra: boolean;
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
    this.ip_config = true;
    this.nat_config = false;
    this.mark_config = false;
    this.ipv6pd = false;
    this.icmpv6ra = false;
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
        this.wifi = true;
      }
    }
    if (dev.controller_name != undefined || dev.controller_id != undefined) {
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
      this.icmpv6ra = true;
    } else if (dev.zone_type === ZoneType.Lan) {
      this.dhcp_v4 = true;
      this.ip_config = false;
      this.icmpv6ra = true;
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

export class TopologyServiceExhibitSwitch {
  carrier: boolean;
  enable_in_boot: boolean;
  zone_type: boolean;
  pppd: boolean;
  ip_config: boolean;
  nat_config: boolean;
  mark_config: boolean;
  ipv6pd: boolean;
  icmpv6ra: boolean;
  firewall: boolean;
  wifi: boolean;
  station: boolean;
  dhcp_v4: boolean;

  constructor(
    config: NetworkIfaceConfig,
    status: LandscapeInterface,
    wifi_info: LandscapeWifiInterface | null,
  ) {
    this.carrier = true;
    this.enable_in_boot = true;
    this.zone_type = true;
    this.pppd = false;
    this.ip_config = true;
    this.nat_config = false;
    this.mark_config = false;
    this.ipv6pd = false;
    this.icmpv6ra = false;
    this.firewall = false;
    this.wifi = false;
    this.station = false;
    this.dhcp_v4 = false;

    if (wifi_info !== null) {
      if (wifi_info.wifi_type.t == WLANTypeTag.Station) {
        this.station = true;
      } else if (wifi_info.wifi_type.t == WLANTypeTag.Ap) {
        this.wifi = true;
      }
    }
    if (
      config.controller_name != undefined ||
      status.controller_id != undefined
    ) {
      this.zone_type = false;
      this.enable_in_boot = false;
      this.ip_config = false;
    }

    if (status.peer_link_id != undefined) {
      this.enable_in_boot = false;
      this.ip_config = false;
    }
    if (status.dev_type === "ppp") {
      this.enable_in_boot = false;
      this.ip_config = false;
      this.zone_type = false;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
    } else if (status.iface_name === "docker0") {
      this.zone_type = false;
      this.ip_config = false;
      this.icmpv6ra = true;
    } else if (config.zone_type === ZoneType.Lan) {
      this.dhcp_v4 = true;
      this.ip_config = false;
      this.icmpv6ra = true;
    } else if (config.zone_type === ZoneType.Wan) {
      this.pppd = true;
      this.ip_config = true;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
    }
  }
}
