import { NetDev } from "@/lib/dev";
import {
  getIfacesOld,
  setController as add_controller,
  createBridge,
  deleteBridge as delete_bridge,
  changeZone as change_zone,
  changeDevStatus as change_iface_status,
  changeWifiMode as change_wifi_mode,
} from "landscape-types/api/interfaces/interfaces";

export {
  add_controller,
  delete_bridge,
  change_zone,
  change_iface_status,
  change_wifi_mode,
};

export async function ifaces(): Promise<NetDev[]> {
  let data = await getIfacesOld();
  return data.map((e: any) => new NetDev(e));
}

export async function create_bridge(name: string) {
  return createBridge({ name });
}
