import type { DHCPv4OfferInfo } from "@/api/service_dhcp_v4";
import { IPv4, IPv4CidrRange } from "ip-num";

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
      `${this.server_ip_addr}/${this.network_mask}`,
    );
    // console.log(end);
    this.ip_range_start = obj?.ip_range_start ?? start;
    this.ip_range_end = obj?.ip_range_end ?? end;
    this.mac_binding_records = obj?.mac_binding_records ?? [];
  }
}

export function get_dhcp_range(cidr: string): [string, string] {
  let range = IPv4CidrRange.fromCidr(cidr);

  // 起始 IP 的数值（bigint）
  const firstIpValue = range.getFirst().getValue();

  // 想取第 2 个 IP（从 0 开始偏移）
  const nth = 2n;
  const nthIpValue = firstIpValue + nth;

  // 构造 IP 对象
  const nthIp = IPv4.fromNumber(nthIpValue);

  return [nthIp.toString(), range.getLast().toString()];
}

export type DHCPv4OfferInfoShow = {
  mac: string;
  ip: string;
  time_left: number;
};

export function conver_to_show(
  data: DHCPv4OfferInfo | null,
): DHCPv4OfferInfoShow[] {
  if (data) {
    const result: DHCPv4OfferInfoShow[] = [];
    let relative_boot_time = data.relative_boot_time;
    for (const each of data.offered_ips) {
      // console.log(each);
      const time_left =
        each.relative_active_time + each.expire_time - relative_boot_time;
      result.push({
        mac: each.mac as unknown as string,
        ip: each.ip,
        time_left: time_left,
      });
    }
    return result;
  } else {
    return [];
  }
}
