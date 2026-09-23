import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type {
  WanLinkConfig,
  WanLinkKindConfig,
} from "@landscape-router/types/api/schemas";
import { get_all_wan_links } from "@/api/wan_links";

export type { WanLinkConfig };

export type WanLinkKind = WanLinkKindConfig["t"];

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

export function wanLinkKind(link: WanLinkConfig): WanLinkKind {
  return link.kind?.t ?? "ethernet";
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

  const byAttachIface = computed(() => {
    const map = new Map<string, WanLinkConfig[]>();
    for (const link of links.value) {
      const list = map.get(link.attach_iface_name) ?? [];
      list.push(link);
      map.set(link.attach_iface_name, list);
    }
    return map;
  });

  /** Kernel devices fully managed by a WAN link (e.g. pppd's ppp iface). */
  const linkManagedIfaces = computed(
    () =>
      new Set(
        links.value
          .filter((link) => wanLinkKind(link) === "pppd")
          .map((link) => wanLinkNetIface(link)),
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
        links.value = await get_all_wan_links();
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
    // 强制发起新请求：PUT/DELETE 之后的刷新不能与轮询中 in-flight 的旧
    // 响应去重复用，否则 UI 会短暂显示修改前的数据。
    loadPromise = null;
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

  function byIface(iface_name: string): WanLinkConfig[] {
    return byAttachIface.value.get(iface_name) ?? [];
  }

  return {
    links,
    options,
    byId,
    byAttachIface,
    linkManagedIfaces,
    loading,
    loaded,
    load,
    ensureLoaded,
    refresh,
    labelFor,
    netIfaceFor,
    byIface,
  };
});
