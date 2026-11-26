import { get_all_wifi_status } from "@/api/services/wifi";
import { defineInterfaceStatusStore } from "./interfaceStatus";

export const useWifiConfigStore = defineInterfaceStatusStore(
  "status_wifi",
  get_all_wifi_status,
);
