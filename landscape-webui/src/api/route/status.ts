import type { RouteStatusView } from "@landscape-router/types/api/schemas";
import { getRoutingStatus } from "@landscape-router/types/api/route/route";

export async function get_route_status(): Promise<RouteStatusView> {
  return await getRoutingStatus();
}
