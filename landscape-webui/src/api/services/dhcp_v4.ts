import type {
  DHCPv4ServiceConfig,
  ServiceStatus,
} from "@landscape-router/types/api/schemas";

import {
  getAllDhcpV4ServiceStatus,
  getDhcpV4ServiceConfig,
  handleDhcpV4ServiceConfig,
  deleteAndStopDhcpV4Service,
} from "@landscape-router/types/api/dhcpv4/dhcpv4";

export async function get_all_dhcp_v4_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllDhcpV4ServiceStatus();
  return new Map(Object.entries(data));
}

export async function get_iface_dhcp_v4_config(
  iface_name: string,
): Promise<DHCPv4ServiceConfig> {
  return getDhcpV4ServiceConfig(iface_name);
}

export async function update_dhcp_v4_config(
  dhcp_v4_config: DHCPv4ServiceConfig,
): Promise<void> {
  await handleDhcpV4ServiceConfig(dhcp_v4_config);
}

export async function stop_and_del_iface_dhcp_v4(name: string): Promise<void> {
  await deleteAndStopDhcpV4Service(name);
}
