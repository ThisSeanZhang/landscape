import type {
  LinkStatus,
  WanLinkConfig,
} from "@landscape-router/types/api/schemas";
import {
  deleteWanLink,
  getAllWanLinks,
  getWanLinkConfig,
  getWanLinkStatuses,
  handleWanLinkConfig,
} from "@landscape-router/types/api/wan-links/wan-links";

export async function get_all_wan_links(): Promise<WanLinkConfig[]> {
  return (await getAllWanLinks()) ?? [];
}

export async function get_wan_link(id: string): Promise<WanLinkConfig | null> {
  return (await getWanLinkConfig(id)) ?? null;
}

export async function get_all_wan_link_statuses(): Promise<
  Map<string, LinkStatus>
> {
  const data = await getWanLinkStatuses();
  const map = new Map<string, LinkStatus>();
  for (const [key, value] of Object.entries(data ?? {})) {
    map.set(key, value as LinkStatus);
  }
  return map;
}

export async function update_wan_link_config(config: WanLinkConfig) {
  await handleWanLinkConfig(config as any);
}

export async function delete_wan_link(id: string) {
  await deleteWanLink(id);
}
