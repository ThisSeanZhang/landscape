import { useLatestHistoryQuery } from "@/composables/useLatestHistoryQuery";
import { defineStore } from "pinia";
import { ref } from "vue";
import { get_connect_global_stats } from "@/api/metric";
import type { ConnectGlobalStats } from "@landscape-router/types/api/schemas";

export const useMetricStore = defineStore("dns_metric", () => {
  const global_history_stats = ref<ConnectGlobalStats | null>(null);

  const {
    loading: globalStatsLoading,
    failed: globalStatsFailed,
    run,
  } = useLatestHistoryQuery();
  function UPDATE_GLOBAL_HISTORY_STATS(force_refresh = false) {
    return run(
      () =>
        get_connect_global_stats(
          force_refresh ? { force_refresh: true } : undefined,
        ),
      (stats) => {
        global_history_stats.value = stats;
      },
    );
  }
  return {
    global_history_stats,
    globalStatsFailed,
    globalStatsLoading,
    UPDATE_GLOBAL_HISTORY_STATS,
  };
});
