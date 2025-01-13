import { interval_fetch_info } from "@/api/sys";
import { LandscapeStatus } from "@/lib/sys";
import { defineStore } from "pinia";
import { ref } from "vue";

export const useSysInfo = defineStore("sysinfo", () => {
  const router_status = ref<LandscapeStatus>(new LandscapeStatus());

  async function UPDATE_INFO() {
    router_status.value = await interval_fetch_info();
  }

  return {
    router_status,
    UPDATE_INFO,
  };
});
