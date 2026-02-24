import { NatServiceConfig } from "@/lib/nat";
import { ServiceStatus } from "@/lib/services";
import {
  getAllNatStatus,
  getIfaceNatConifg,
  handleIfaceNatStatus,
  deleteAndStopIfaceNat,
} from "landscape-types/api/nat-service/nat-service";

export async function get_all_nat_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllNatStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_iface_nat_config(
  iface_name: string,
): Promise<NatServiceConfig> {
  const data = await getIfaceNatConifg(iface_name);
  return new NatServiceConfig(data as any);
}

export async function update_iface_nat_config(
  nat_config: NatServiceConfig,
): Promise<void> {
  await handleIfaceNatStatus(nat_config as any);
}

export async function stop_and_del_iface_nat(name: string): Promise<void> {
  await deleteAndStopIfaceNat(name);
}
