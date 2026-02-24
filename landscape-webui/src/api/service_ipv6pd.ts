import { IPV6PDServiceConfig } from "@/lib/ipv6pd";
import { ServiceStatus } from "@/lib/services";
import {
  getAllIpv6pdStatus,
  getIfacePdConfig,
  handleIfacePd,
  deleteAndStopIpv6pdService,
  getCurrentIpPrefixInfo,
} from "@landscape-router/types/api/ipv6-pd/ipv6-pd";
import type { LDIAPrefix } from "@landscape-router/types/api/schemas";

// LDIAPrefix is now directly imported from generated types

export async function get_all_ipv6pd_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllIpv6pdStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_ipv6pd_config(
  iface_name: string,
): Promise<IPV6PDServiceConfig> {
  const data = await getIfacePdConfig(iface_name);
  return new IPV6PDServiceConfig(data);
}

export async function get_current_ip_prefix_info(): Promise<
  Map<string, LDIAPrefix | null>
> {
  const data = await getCurrentIpPrefixInfo();
  const map = new Map<string, LDIAPrefix | null>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as LDIAPrefix | null);
  }
  return map;
}

export async function update_ipv6pd_config(
  ipv6pd_config: IPV6PDServiceConfig,
): Promise<void> {
  await handleIfacePd(ipv6pd_config as any);
}

export async function stop_and_del_iface_ipv6pd(name: string): Promise<void> {
  await deleteAndStopIpv6pdService(name);
}

export type { LDIAPrefix };
