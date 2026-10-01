import { getLanDevices } from "@landscape-router/types/api/lan-devices/lan-devices";
import type { LanDeviceView } from "@landscape-router/types/api/schemas";

export type { LanDeviceView };

export async function get_lan_devices(): Promise<LanDeviceView[]> {
  return (await getLanDevices()) ?? [];
}
