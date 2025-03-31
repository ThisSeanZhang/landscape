import { Netmask } from "netmask";
import { ServiceStatus } from "./services";

export class DHCPv4ServiceConfig {
  iface_name: string;
  enable: boolean;
  config: DHCPv4ServerConfig;

  constructor(obj?: {
    iface_name: string;
    enable?: boolean;
    config?: DHCPv4ServerConfig;
  }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.config = new DHCPv4ServerConfig(obj?.config);
  }
}

export interface MacBindingRecord {
  mac: string;
  ip: string;
  expire_time: number;
}

export class DHCPv4ServerConfig {
  options: any[];
  server_ip_addr: string;
  network_mask: number;
  ip_range_start: string;
  ip_range_end: string | undefined;
  mac_binding_records: MacBindingRecord[];

  constructor(obj?: {
    options?: any[];
    server_ip_addr?: string;
    network_mask?: number;
    ip_range_start?: string;
    ip_range_end?: string;
    mac_binding_records?: MacBindingRecord[];
  }) {
    this.options = obj?.options ?? [];
    this.server_ip_addr = obj?.server_ip_addr ?? "192.168.5.1";
    this.network_mask = obj?.network_mask ?? 24;
    const [start, end] = get_dhcp_range(
      `${this.server_ip_addr}/${this.network_mask}`
    );
    // console.log(end);
    this.ip_range_start = obj?.ip_range_start ?? start;
    this.ip_range_end = obj?.ip_range_end ?? end;
    this.mac_binding_records = obj?.mac_binding_records ?? [];
  }
}

export function get_dhcp_range(cidr: string): [string, string] {
  let block = new Netmask(cidr);
  let sec_ip = "";
  block.forEach((ip, _, index) => {
    if (index == 1) {
      sec_ip = ip;
    }
  });
  return [sec_ip, block.broadcast];
}

export class DHCPv4ServiceStatus {
  status: ServiceStatus;
  data?: DHCPv4OfferInfo;

  constructor(obj?: { status: ServiceStatus; data?: DHCPv4OfferInfo }) {
    this.status = new ServiceStatus(obj?.status);
    this.data = obj?.data;
  }

  get_color(themeVars: any) {
    return this.status.get_color(themeVars);
  }
}

export type DHCPv4OfferInfo = {
  relative_boot_time: number;
  offered_ips: DHCPv4OfferInfoItem[];
};
export type DHCPv4OfferInfoShow = {
  mac: string;
  ip: string;
  time_left: number;
};

export type DHCPv4OfferInfoItem = {
  mac: string;
  ip: string;
  relative_active_time: number;
  expire_time: number;
};

export function conver_to_show(data?: DHCPv4OfferInfo): DHCPv4OfferInfoShow[] {
  if (data) {
    const result: DHCPv4OfferInfoShow[] = [];
    let relative_boot_time = data.relative_boot_time;
    for (const each of data.offered_ips) {
      // console.log(each);
      const time_left =
        each.relative_active_time + each.expire_time - relative_boot_time;
      result.push({
        mac: each.mac,
        ip: each.ip,
        time_left: time_left,
      });
    }
    return result;
  } else {
    return [];
  }
}
