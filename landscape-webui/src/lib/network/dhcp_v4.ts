import { IPv4, IPv4CidrRange } from "ip-num";
import type { DHCPv4ServiceConfig } from "@landscape-router/types/api/schemas";

export function createDhcpV4Config(
  ifaceName: string,
  stored?: DHCPv4ServiceConfig,
) {
  const config = stored?.config;
  const serverIp = config?.server_ip_addr ?? "192.168.5.1";
  const mask = config?.network_mask ?? 24;
  const [start, end] = get_dhcp_range(`${serverIp}/${mask}`);
  return {
    iface_name: stored?.iface_name ?? ifaceName,
    enable: stored?.enable ?? true,
    update_at: stored?.update_at,
    config: {
      custom_options: config?.custom_options ?? [],
      address_lease_time: config?.address_lease_time ?? null,
      server_ip_addr: serverIp,
      network_mask: mask,
      ip_range_start: config?.ip_range_start ?? start,
      ip_range_end: config?.ip_range_end ?? end,
    },
  } satisfies DHCPv4ServiceConfig;
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
