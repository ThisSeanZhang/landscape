import { ServiceStatus } from "@/lib/services";
import type { RouteLanServiceConfig } from "landscape-types/api/schemas";
import {
  getAllRouteLanStatus,
  getRouteLanConfig,
  handleRouteLanStatus,
  deleteAndStopRouteLan,
} from "landscape-types/api/route-lan/route-lan";

export async function get_all_route_lan_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllRouteLanStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_route_lan_config(
  id: string,
): Promise<RouteLanServiceConfig> {
  return await getRouteLanConfig(id);
}

export async function update_route_lans_config(
  config: RouteLanServiceConfig,
): Promise<void> {
  await handleRouteLanStatus(config);
}

export async function del_route_lans(iface_name: string): Promise<void> {
  await deleteAndStopRouteLan(iface_name);
}
