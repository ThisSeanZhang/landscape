import api from "@/api";
import { IfaceCpuSoftBalance } from "@/rust_bindings/common/iface";
import { IfacesInfo } from "@/rust_bindings/iface";

export async function ifaces(): Promise<IfacesInfo> {
  let data = await api.api.get("iface");
  // console.log(data.data);
  return data.data;
}

export async function manage_iface(dev_name: String): Promise<IfacesInfo> {
  let data = await api.api.post(`iface/manage/${dev_name}`);
  // console.log(data.data);
  return data.data;
}

export async function get_iface_cpu_balance(
  dev_name: String
): Promise<IfaceCpuSoftBalance | undefined> {
  let data = await api.api.get(`iface/${dev_name}/cpu_balance`);
  // console.log(data.data);
  return data.data;
}

export async function set_iface_cpu_balance(
  dev_name: String,
  cpu_balance: IfaceCpuSoftBalance | undefined
): Promise<void> {
  let data = await api.api.post(`iface/${dev_name}/cpu_balance`, {
    ...cpu_balance,
  });
  // console.log(data.data);
  return data.data;
}
