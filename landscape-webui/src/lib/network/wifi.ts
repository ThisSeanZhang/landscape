import type { WifiServiceConfig } from "@landscape-router/types/api/schemas";

export function createWifiConfig(
  ifaceName: string,
  stored?: WifiServiceConfig,
): WifiServiceConfig {
  return {
    iface_name: stored?.iface_name ?? ifaceName,
    enable: stored?.enable ?? true,
    config: stored?.config ?? "",
    update_at: stored?.update_at,
  };
}
