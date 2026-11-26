import { get_all_dhcp_v4_status } from "@/api/services/dhcp_v4";
import { defineInterfaceStatusStore } from "./interfaceStatus";

export const useDHCPv4ConfigStore = defineInterfaceStatusStore(
  "status_dhcp_v4",
  get_all_dhcp_v4_status,
);
