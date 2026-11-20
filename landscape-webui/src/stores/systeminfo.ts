import type { LandscapeStatus } from "@landscape-router/types/api/schemas";
import { interval_fetch_info } from "@/api/sys";
import { createLandscapeStatus } from "@/lib/sys";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useSysInfo = defineStore("sysinfo", () => {
  const router_status = ref<LandscapeStatus>(createLandscapeStatus());

  async function UPDATE_INFO() {
    router_status.value = await interval_fetch_info();
  }

  return {
    router_status,
    UPDATE_INFO,
  };
});
