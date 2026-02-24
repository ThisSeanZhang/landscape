import { WifiServiceConfig } from "@/lib/wifi";
import { ServiceStatus } from "@/lib/services";
import {
  getAllWifiServiceStatus,
  getWifiServiceConfig,
  handleWifiServiceConfig,
  deleteAndStopWifiService,
} from "landscape-types/api/wi-fi/wi-fi";

export async function get_all_wifi_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllWifiServiceStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_wifi_config(
  iface_name: string,
): Promise<WifiServiceConfig> {
  const data = await getWifiServiceConfig(iface_name);
  return new WifiServiceConfig(data);
}

export async function update_wifi_config(
  wifi_config: WifiServiceConfig,
): Promise<void> {
  await handleWifiServiceConfig(wifi_config as any);
}

export async function stop_and_del_iface_wifi(name: string): Promise<void> {
  await deleteAndStopWifiService(name);
}
