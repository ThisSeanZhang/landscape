import { IfaceIpServiceConfig } from "@/lib/service_ipconfig";
import { ServiceStatus } from "@/lib/services";
import {
  getAllIpconfigStatus,
  getIpconfigServiceConfig,
  handleIfaceServiceStatus,
  deleteAndStopIpconfigService,
} from "@landscape-router/types/api/ip-config/ip-config";

export async function get_all_ipconfig_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllIpconfigStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_server_config(
  iface_name: string,
): Promise<IfaceIpServiceConfig> {
  const data = await getIpconfigServiceConfig(iface_name);
  return new IfaceIpServiceConfig(data as any);
}

export async function update_iface_server_config(
  iface_config: IfaceIpServiceConfig,
): Promise<void> {
  await handleIfaceServiceStatus(iface_config as any);
}

export async function stop_and_del_iface_config(name: string): Promise<void> {
  await deleteAndStopIpconfigService(name);
}
