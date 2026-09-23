import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type { LandscapeApiRespVecWanLinkConfigDataItem as WanLinkConfig } from "@landscape-router/types/api/schemas";
import { get_wan_links } from "@/api/iface";

export type { WanLinkConfig };

export interface WanLinkOption {
  label: string;
  value: string;
  net_iface: string;
}

/** Kernel interface a link presents at runtime. */
export function wanLinkNetIface(link: WanLinkConfig): string {
  if (link.kind?.t === "pppd") {
    return link.kind.ppp_iface_name;
  }
  return link.attach_iface_name;
}

/** Human label for a link: remark when set, otherwise the net iface. */
export function wanLinkLabel(link: WanLinkConfig): string {
  const netIface = wanLinkNetIface(link);
  const remark = link.name?.trim();
  return remark && remark !== netIface ? `${remark} (${netIface})` : netIface;
}

export const useWanLinkStore = defineStore("wan_link", () => {
  const links = ref<WanLinkConfig[]>([]);
  const loading = ref(false);
  const loaded = ref(false);
  let loadPromise: Promise<void> | null = null;

  const byId = computed(
    () =>
      new Map(
        links.value
          .filter((link): link is WanLinkConfig & { id: string } => !!link.id)
          .map((link) => [link.id, link] as const),
      ),
  );

  const options = computed<WanLinkOption[]>(() =>
    links.value
      .filter((link): link is WanLinkConfig & { id: string } => !!link.id)
      .map((link) => ({
        label: wanLinkLabel(link),
        value: link.id,
        net_iface: wanLinkNetIface(link),
      })),
  );

  function load(): Promise<void> {
    if (loadPromise) return loadPromise;
    loading.value = true;
    loadPromise = (async () => {
      try {
        links.value = (await get_wan_links()) ?? [];
        loaded.value = true;
      } catch (error) {
        console.error("Failed to fetch wan links:", error);
      } finally {
        loading.value = false;
        loadPromise = null;
      }
    })();
    return loadPromise;
  }

  function ensureLoaded(): Promise<void> {
    if (loaded.value) return Promise.resolve();
    return load();
  }

  function refresh(): Promise<void> {
    return load();
  }

  function labelFor(linkId: string | undefined | null): string {
    if (!linkId) return "";
    const link = byId.value.get(linkId);
    return link ? wanLinkLabel(link) : linkId;
  }

  function netIfaceFor(linkId: string | undefined | null): string {
    if (!linkId) return "";
    const link = byId.value.get(linkId);
    return link ? wanLinkNetIface(link) : "";
  }

  return {
    links,
    options,
    loading,
    loaded,
    ensureLoaded,
    refresh,
    labelFor,
    netIfaceFor,
  };
});
