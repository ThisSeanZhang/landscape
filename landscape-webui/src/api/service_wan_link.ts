import { WanLink, wan_link_from_payload } from "@/lib/wan_link";
import type {
  WanLinkConfig,
  WanLinkStatus,
} from "@landscape-router/types/api/schemas";
import {
  createWanLink,
  deleteWanLink,
  getAllWanLinkStatus,
  listWanLinks,
  updateWanLink,
} from "@landscape-router/types/api/wan-link/wan-link";

export async function get_all_wan_links(): Promise<WanLink[]> {
  const data = await listWanLinks();
  return (data ?? []).map((each) =>
    wan_link_from_payload(each as WanLinkConfig),
  );
}

export async function get_wan_link_status(): Promise<
  Map<string, WanLinkStatus>
> {
  const data = await getAllWanLinkStatus({ silent: true });
  const map = new Map<string, WanLinkStatus>();
  for (const [key, value] of Object.entries(data ?? {})) {
    map.set(key, value as WanLinkStatus);
  }
  return map;
}

export async function create_wan_link(link: WanLink): Promise<WanLink> {
  // Strip the server-assigned id/update_at the local model carries by
  // default; the create endpoint ignores them, but a clean body is explicit.
  const { id: _id, update_at: _updateAt, ...body } = link;
  const payload = (await createWanLink(body)) as WanLinkConfig;
  return wan_link_from_payload(payload);
}

export async function update_wan_link(link: WanLink): Promise<WanLink> {
  const { id, update_at, ...body } = link;
  if (update_at === undefined) {
    throw new Error("update_wan_link: missing update_at (stale form state)");
  }
  const payload = (await updateWanLink(id, {
    ...body,
    id,
    update_at,
  })) as WanLinkConfig;
  return wan_link_from_payload(payload);
}

export async function stop_and_del_wan_link(id: string): Promise<void> {
  await deleteWanLink(id);
}
