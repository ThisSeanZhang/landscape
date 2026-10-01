import { IPv4, IPv4CidrRange } from "ip-num";
import type { CustomDhcpOption } from "@landscape-router/types/api/schemas";

export class DHCPv4ServiceConfig {
  iface_name: string;
  enable: boolean;
  config: DHCPv4ServerConfig;
  update_at?: number;

  constructor(obj?: {
    iface_name: string;
    enable?: boolean;
    config?: DHCPv4ServerConfig;
    update_at?: number;
  }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.config = new DHCPv4ServerConfig(obj?.config);
    this.update_at = obj?.update_at;
  }
}

export class DHCPv4ServerConfig {
  custom_options: CustomDhcpOption[];
  address_lease_time?: number;
  server_ip_addr: string;
  network_mask: number;
  ip_range_start: string;
  ip_range_end: string | undefined;

  constructor(obj?: {
    custom_options?: CustomDhcpOption[];
    address_lease_time?: number;
    server_ip_addr?: string;
    network_mask?: number;
    ip_range_start?: string;
    ip_range_end?: string;
  }) {
    this.custom_options = obj?.custom_options ?? [];
    this.address_lease_time = obj?.address_lease_time;
    this.server_ip_addr = obj?.server_ip_addr ?? "192.168.5.1";
    this.network_mask = obj?.network_mask ?? 24;
    const [start, end] = get_dhcp_range(
      `${this.server_ip_addr}/${this.network_mask}`,
    );
    // console.log(end);
    this.ip_range_start = obj?.ip_range_start ?? start;
    this.ip_range_end = obj?.ip_range_end ?? end;
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
