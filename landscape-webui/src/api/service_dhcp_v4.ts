import { DHCPv4ServiceConfig } from "@/lib/dhcp_v4";
import { ServiceStatus } from "@/lib/services";
import {
  getAllDhcpV4ServiceStatus,
  getAllDhcpV4AssignedIps,
  getAllIfaceArpScanInfo,
  getDhcpV4AssignedIpsByIfaceName,
  getDhcpV4ServiceConfig,
  handleDhcpV4ServiceConfig,
  deleteAndStopDhcpV4Service,
} from "@landscape-router/types/api/dhcpv4/dhcpv4";
import type {
  DHCPv4OfferInfo as DHCPv4OfferInfoType,
  ArpScanInfo as ArpScanInfoType,
} from "@landscape-router/types/api/schemas";

export type DHCPv4OfferInfo = DHCPv4OfferInfoType;
export type ArpScanInfo = ArpScanInfoType;

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

export async function get_dhcp_v4_assigned_ips(): Promise<
  Map<string, DHCPv4OfferInfo | null>
> {
  const data = await getAllDhcpV4AssignedIps();
  const map = new Map<string, DHCPv4OfferInfo | null>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as DHCPv4OfferInfo);
  }
  return map;
}

export async function get_all_iface_arp_scan_info(): Promise<
  Map<string, ArpScanInfo[]>
> {
  const data = await getAllIfaceArpScanInfo();
  const map = new Map<string, ArpScanInfo[]>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ArpScanInfo[]);
  }
  return map;
}

export async function get_dhcp_v4_assigned_ips_by_iface_name(
  iface_name: string,
): Promise<DHCPv4OfferInfo | null> {
  return (await getDhcpV4AssignedIpsByIfaceName(
    iface_name,
  )) as DHCPv4OfferInfo | null;
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
