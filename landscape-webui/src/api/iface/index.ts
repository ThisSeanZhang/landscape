import {
  getIfacesOld,
  getIfacesNew,
  getWanIfaces,
  manageIface,
  getCpuBalance,
  setCpuBalance,
} from "@landscape-router/types/api/interfaces/interfaces";
import type { IfaceCpuSoftBalance } from "@landscape-router/types/api/schemas";

export {
  getIfacesOld as ifaces,
  getIfacesNew as new_ifaces,
  getWanIfaces as get_wan_ifaces,
  manageIface as manage_iface,
  getCpuBalance as get_iface_cpu_balance,
};

export async function set_iface_cpu_balance(
  dev_name: string,
  cpu_balance: IfaceCpuSoftBalance | undefined,
) {
  return setCpuBalance(dev_name, cpu_balance ?? null);
}
