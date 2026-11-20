import { defineStore } from "pinia";
import { ref } from "vue";
import { get_connect_global_stats } from "@/api/metric";
import type { ConnectGlobalStats } from "@landscape-router/types/api/schemas";

export const useMetricStore = defineStore("dns_metric", () => {
  const global_history_stats = ref<ConnectGlobalStats | null>(null);

  async function UPDATE_GLOBAL_HISTORY_STATS(force_refresh = false) {
    global_history_stats.value = await get_connect_global_stats(
      force_refresh ? { force_refresh: true } : undefined,
    );
  }

  return { global_history_stats, UPDATE_GLOBAL_HISTORY_STATS };
});
