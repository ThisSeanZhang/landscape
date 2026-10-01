import { DHCPv4ServiceConfig } from "@/lib/dhcp_v4";
import { ServiceStatus } from "@/lib/services";
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
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_dhcp_v4_config(
  iface_name: string,
): Promise<DHCPv4ServiceConfig> {
  const data = await getDhcpV4ServiceConfig(iface_name);
  return new DHCPv4ServiceConfig(data as any);
}

export async function update_dhcp_v4_config(
  dhcp_v4_config: DHCPv4ServiceConfig,
): Promise<void> {
  await handleDhcpV4ServiceConfig(dhcp_v4_config as any);
}

export async function stop_and_del_iface_dhcp_v4(name: string): Promise<void> {
  await deleteAndStopDhcpV4Service(name);
}
