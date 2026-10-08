import { get_all_wan_links, get_wan_link_status } from "@/api/service_wan_link";
import { WanLink } from "@/lib/wan_link";
import type { WanLinkStatus } from "@landscape-router/types/api/schemas";
import { defineStore } from "pinia";
import { computed, ComputedRef, ref } from "vue";

/**
 * The WAN link set + per-link per-section runtime status. The topology stays
 * iface-centric: nodes resolve their link through the two indexes below.
 */
export const useWanLinkStore = defineStore("wan_link", () => {
  const links = ref<WanLink[]>([]);
  const status = ref<Map<string, WanLinkStatus>>(
    new Map<string, WanLinkStatus>(),
  );

  async function UPDATE_INFO() {
    // Both requests fail independently (e.g. backend restarting): keep the
    // last values so the global poll loop stays alive.
    const [links_result, status_result] = await Promise.all([
      get_all_wan_links().catch(() => undefined),
      get_wan_link_status().catch(() => undefined),
    ]);
    if (links_result !== undefined) {
      links.value = links_result;
    }
    if (status_result !== undefined) {
      status.value = status_result;
    }
  }

  /** ethernet-class links by their attach iface */
  const by_attach_iface = computed(() => {
    const map = new Map<string, WanLink>();
    for (const link of links.value) {
      if (link.kind.t !== "pppd" && !map.has(link.attach_iface_name)) {
        map.set(link.attach_iface_name, link);
      }
    }
    return map;
  });

  /** pppd links by their ppp device name */
  const by_ppp_iface = computed(() => {
    const map = new Map<string, WanLink>();
    for (const link of links.value) {
      const ppp_iface_name = link.ppp_iface_name;
      if (ppp_iface_name !== undefined && !map.has(ppp_iface_name)) {
        map.set(ppp_iface_name, link);
      }
    }
    return map;
  });

  function GET_LINK_BY_IFACE(name: string): ComputedRef<WanLink | undefined> {
    return computed(() => by_attach_iface.value.get(name));
  }

  function GET_PPPD_LINK_BY_IFACE(
    name: string,
  ): ComputedRef<WanLink | undefined> {
    return computed(() => by_ppp_iface.value.get(name));
  }

  /** Resolve the link that owns a node: pppd links by ppp iface first
   * (ppp cards carry their own NAT/FW/PD/MSS sections), ethernet-class by
   * attach iface otherwise. */
  function RESOLVE_NODE_LINK(name: string): ComputedRef<WanLink | undefined> {
    return computed(
      () => by_ppp_iface.value.get(name) ?? by_attach_iface.value.get(name),
    );
  }

  function GET_STATUS_BY_ID(
    id: string | undefined,
  ): ComputedRef<WanLinkStatus | undefined> {
    return computed(() =>
      id === undefined ? undefined : status.value.get(id),
    );
  }

  return {
    links,
    status,
    UPDATE_INFO,
    GET_LINK_BY_IFACE,
    GET_PPPD_LINK_BY_IFACE,
    RESOLVE_NODE_LINK,
    GET_STATUS_BY_ID,
  };
});
