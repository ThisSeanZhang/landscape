import { get_all_route_wan_status } from "@/api/route/wan";
import { defineInterfaceStatusStore } from "./interfaceStatus";

export const useRouteWanConfigStore = defineInterfaceStatusStore(
  "status_route_wan",
  get_all_route_wan_status,
);
