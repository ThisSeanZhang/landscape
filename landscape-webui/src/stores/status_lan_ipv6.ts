import { get_all_lan_ipv6_status } from "@/api/service_lan_ipv6";
import { defineInterfaceStatusStore } from "./interfaceStatus";

export const useLanIPv6Store = defineInterfaceStatusStore(
  "status_lan_ipv6",
  get_all_lan_ipv6_status,
);
