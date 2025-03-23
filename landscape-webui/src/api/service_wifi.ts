import { WifiServiceConfig } from "@/lib/wifi";
import api from ".";
import { ServiceStatus } from "@/lib/services";

export async function get_all_wifi_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await api.api.get(`services/wifi/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_wifi_config(
  iface_name: string
): Promise<WifiServiceConfig> {
  let data = await api.api.get(`services/wifi/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_wifi_config(
  wifi_config: WifiServiceConfig
): Promise<void> {
  let data = await api.api.post(`services/wifi`, {
    ...wifi_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_wifi(name: string): Promise<void> {
  return api.api.delete(`services/wifi/${name}`);
}
