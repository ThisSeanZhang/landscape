import { get_all_route_lan_status } from "@/api/route/lan";
import { defineInterfaceStatusStore } from "./interfaceStatus";

export const useRouteLanConfigStore = defineInterfaceStatusStore(
  "status_route_lan",
  get_all_route_lan_status,
);
