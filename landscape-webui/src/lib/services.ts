import { NetDev } from "./dev";
import { ZoneType } from "./service_ipconfig";

export enum ServiceStatusType {
  Staring = "staring",
  Running = "running",
  Stopping = "stopping",
  Stop = "stop",
}

export class ServiceStatus {
  t: ServiceStatusType;
  message: undefined | string;

  constructor(obj?: { t: ServiceStatusType; message?: string }) {
    this.t = obj?.t ?? ServiceStatusType.Stop;
    this.message = obj?.message;
  }

  get_color(themeVars: any) {
    return this.t === ServiceStatusType.Running ? themeVars.successColor : "";
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
  icmpv6ra: boolean;
  firewall: boolean;

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

    if (dev.controller != undefined || dev.controller_id != undefined) {
      this.zone_type = false;
      this.enable_in_boot = false;
      this.ip_config = false;
    }

    if (dev.peer_link_id != undefined) {
      this.enable_in_boot = false;
      this.ip_config = false;
    }
    if (dev.dev_type === "Ppp") {
      this.enable_in_boot = false;
      this.ip_config = false;
      this.zone_type = false;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
    } else if (dev.name === "docker0") {
      this.zone_type = false;
      this.ip_config = false;
      this.icmpv6ra = true;
    } else if (dev.zone_type === ZoneType.Lan) {
      this.ip_config = true;
      this.icmpv6ra = true;
    } else if (dev.zone_type === ZoneType.Wan) {
      this.pppd = true;
      this.ip_config = true;
      this.nat_config = true;
      this.mark_config = true;
      this.ipv6pd = true;
      this.firewall = true;
    }
  }
}
