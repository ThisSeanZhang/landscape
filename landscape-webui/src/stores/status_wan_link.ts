import { get_all_wan_link_statuses } from "@/api/wan_links";
import type { LinkStatus } from "@landscape-router/types/api/schemas";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useWanLinkStatusStore = defineStore("status_wan_link", () => {
  const status = ref<Map<string, LinkStatus>>(new Map<string, LinkStatus>());

  async function UPDATE_INFO() {
    status.value = await get_all_wan_link_statuses();
  }

  return {
    status,
    UPDATE_INFO,
  };
});
