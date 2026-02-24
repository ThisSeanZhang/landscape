import { FirewallServiceConfig } from "@/lib/firewall";
import { ServiceStatus } from "@/lib/services";
import {
  getAllFirewallServiceStatus,
  getFirewallServiceConfig,
  handleFirewallServiceConfig,
  deleteAndStopFirewallService,
} from "@landscape-router/types/api/firewall-service/firewall-service";

export async function get_all_firewall_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllFirewallServiceStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_firewall_config(
  iface_name: string,
): Promise<FirewallServiceConfig> {
  const data = await getFirewallServiceConfig(iface_name);
  return new FirewallServiceConfig(data);
}

export async function update_firewall_config(
  firewall_config: FirewallServiceConfig,
): Promise<void> {
  await handleFirewallServiceConfig(firewall_config as any);
}

export async function stop_and_del_iface_firewall(name: string): Promise<void> {
  await deleteAndStopFirewallService(name);
}
