import { NetDev } from "@/lib/network/dev";
import axios from "axios";
import {
  getIfacesOld,
  setController as add_controller,
  createBridge,
  deleteBridge as delete_bridge,
  changeZone as change_zone,
  changeDevStatus as change_iface_status,
  changeWifiMode as change_wifi_mode,
} from "@landscape-router/types/api/interfaces/interfaces";
import { applyInterceptors } from "@/api";

const networkAxios = applyInterceptors(
  axios.create({ baseURL: "/api/v1/interfaces", timeout: 30000 }),
);

export {
  add_controller,
  delete_bridge,
  change_zone,
  change_iface_status,
  change_wifi_mode,
};

export async function ifaces(): Promise<NetDev[]> {
  const data = await getIfacesOld();
  return data.map((iface) => new NetDev(iface));
}

export async function create_bridge(name: string) {
  return createBridge({ name });
}

export async function change_iface_boot_status(
  iface_name: string,
  enable_in_boot: boolean,
) {
  return networkAxios.post(
    `/${encodeURIComponent(iface_name)}/boot/${enable_in_boot}`,
  );
}
