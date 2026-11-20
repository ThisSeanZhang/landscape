import type {
  WifiServiceConfig,
  ServiceStatus,
} from "@landscape-router/types/api/schemas";

import {
  getAllWifiServiceStatus,
  getWifiServiceConfig,
  handleWifiServiceConfig,
  deleteAndStopWifiService,
} from "@landscape-router/types/api/wi-fi/wi-fi";

export async function get_all_wifi_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllWifiServiceStatus();
  return new Map(Object.entries(data));
}

export async function get_iface_wifi_config(
  iface_name: string,
): Promise<WifiServiceConfig> {
  return getWifiServiceConfig(iface_name);
}

export async function update_wifi_config(
  wifi_config: WifiServiceConfig,
): Promise<void> {
  await handleWifiServiceConfig(wifi_config);
}

export async function stop_and_del_iface_wifi(name: string): Promise<void> {
  await deleteAndStopWifiService(name);
}
