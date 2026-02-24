import { ServiceStatus } from "@/lib/services";
import type { MSSClampServiceConfig } from "landscape-types/api/schemas";
import {
  getAllMssClampServiceStatus,
  getMssClampServiceConfig,
  handleMssClampServiceConfig,
  deleteAndStopMssClampService,
} from "landscape-types/api/mss-clamp/mss-clamp";

export async function get_all_mss_clamp_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllMssClampServiceStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_mss_clamp_config(
  iface_name: string,
): Promise<MSSClampServiceConfig> {
  return await getMssClampServiceConfig(iface_name);
}

export async function update_mss_clamp_config(
  mss_clamp_config: MSSClampServiceConfig,
): Promise<void> {
  await handleMssClampServiceConfig(mss_clamp_config);
}

export async function stop_and_del_iface_mss_clamp(
  name: string,
): Promise<void> {
  await deleteAndStopMssClampService(name);
}
