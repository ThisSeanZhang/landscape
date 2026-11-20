import type {
  ServiceStatus,
  RouteWanServiceConfig,
} from "@landscape-router/types/api/schemas";

import {
  getAllRouteWanStatus,
  getRouteWanConfig,
  handleRouteWanStatus,
  deleteAndStopRouteWan,
} from "@landscape-router/types/api/route-wan/route-wan";

export async function get_all_route_wan_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllRouteWanStatus();
  return new Map(Object.entries(data));
}

export async function get_route_wan_config(
  id: string,
): Promise<RouteWanServiceConfig> {
  return await getRouteWanConfig(id);
}

export async function update_route_wans_config(
  config: RouteWanServiceConfig,
): Promise<void> {
  await handleRouteWanStatus(config);
}

export async function del_route_wans(iface_name: string): Promise<void> {
  await deleteAndStopRouteWan(iface_name);
}
