import { PPPDServiceConfig } from "@/lib/pppd";
import { ServiceStatus } from "@/lib/services";
import {
  getAllPppdStatus,
  getAllPppdConfigs,
  getIfacePppdConfig,
  handleIfacePppdConfig,
  deleteAndStopIfacePppd,
  deleteAndStopIfacePppdByAttachIfaceName,
  getIfacePppdConfigByAttachIfaceName,
} from "landscape-types/api/pppo-e/pppo-e";

export async function get_all_pppd_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllPppdStatus();
  const map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data)) {
    map.set(key, value as ServiceStatus);
  }
  return map;
}

export async function get_all_iface_pppd_config(): Promise<
  PPPDServiceConfig[]
> {
  const data = await getAllPppdConfigs();
  return data as PPPDServiceConfig[];
}

export async function get_iface_pppd_config(
  iface_name: string,
): Promise<PPPDServiceConfig> {
  const data = await getIfacePppdConfig(iface_name);
  return data as PPPDServiceConfig;
}

export async function update_iface_pppd_config(
  pppd_config: PPPDServiceConfig,
): Promise<void> {
  await handleIfacePppdConfig(pppd_config as any);
}

export async function stop_and_del_iface_pppd(name: string): Promise<void> {
  await deleteAndStopIfacePppd(name);
}

export async function delete_and_stop_iface_pppd_by_attach_iface_name(
  attach_iface_name: string,
): Promise<void> {
  await deleteAndStopIfacePppdByAttachIfaceName(attach_iface_name);
}

export async function get_attach_iface_pppd_config(
  iface_name: string,
): Promise<PPPDServiceConfig[]> {
  const data = await getIfacePppdConfigByAttachIfaceName(iface_name);
  return data as PPPDServiceConfig[];
}
