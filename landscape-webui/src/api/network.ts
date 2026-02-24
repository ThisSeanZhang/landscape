import { NetDev } from "@/lib/dev";
import {
  getIfaces,
  setController as add_controller,
  createBridge,
  deleteBridge as delete_bridge,
  changeZone as change_zone,
  changeDevStatus as change_iface_status,
  changeWifiMode as change_wifi_mode,
} from "landscape-types/api/iface/iface";

export {
  add_controller,
  delete_bridge,
  change_zone,
  change_iface_status,
  change_wifi_mode,
};

export async function ifaces(): Promise<NetDev[]> {
  let data = await getIfaces();
  return data.map((e: any) => new NetDev(e));
}

export async function create_bridge(name: string) {
  return createBridge({ name });
}
