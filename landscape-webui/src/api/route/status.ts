import type { RouteStatusView } from "@landscape-router/types/api/schemas";
import { getRoutingStatus } from "@landscape-router/types/api/route/route";

export type {
  RouteStatusView,
  WanRouteEntry,
  Ipv4LanRouteEntry,
  Ipv6LanRouteEntry,
  RouteOwner,
  RouteTargetInfo,
  LanRouteInfo,
  LanRouteMode,
  LanIPv6RouteKey,
} from "@landscape-router/types/api/schemas";

export async function get_route_status(): Promise<RouteStatusView> {
  return await getRoutingStatus();
}
