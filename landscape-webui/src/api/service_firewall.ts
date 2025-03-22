import { FirewallServiceConfig } from "@/lib/firewall";
import api from ".";
import { ServiceStatus } from "@/lib/services";

export async function get_all_firewall_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await api.api.get(`services/firewall/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_firewall_config(
  iface_name: string
): Promise<FirewallServiceConfig> {
  let data = await api.api.get(`services/firewall/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_firewall_config(
  firewall_config: FirewallServiceConfig
): Promise<void> {
  let data = await api.api.post(`services/firewall`, {
    ...firewall_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_firewall(name: string): Promise<void> {
  return api.api.delete(`services/firewall/${name}`);
}
