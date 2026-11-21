import type { LandscapeStatus } from "@landscape-router/types/api/schemas";
import { interval_fetch_info } from "@/api/sys";
import { createLandscapeStatus } from "@/lib/sys";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useSysInfo = defineStore("sysinfo", () => {
  const router_status = ref<LandscapeStatus>(createLandscapeStatus());

  const lastSampleAt = ref<number>();
  const sampleFailed = ref(false);

  async function UPDATE_INFO() {
    try {
      router_status.value = await interval_fetch_info();
      lastSampleAt.value = Date.now();
      sampleFailed.value = false;
    } catch (error) {
      sampleFailed.value = true;
      throw error;
    }
  }

  return {
    router_status,
    lastSampleAt,
    sampleFailed,
    UPDATE_INFO,
  };
});
