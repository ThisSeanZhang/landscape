import { defineStore } from "pinia";
import { ref } from "vue";
import { get_iface_stats } from "@/api/metric";
import type { IfaceRealtimeStat } from "@landscape-router/types/api/schemas";

export const useTopologyMetricsStore = defineStore("topology_metrics", () => {
  const active = ref(false);
  const iface_stats = ref<IfaceRealtimeStat[]>([]);
  let pending: Promise<void> | undefined;

  function UPDATE_INFO() {
    if (!active.value) return;
    pending ??= get_iface_stats()
      .then((stats) => {
        iface_stats.value = stats;
      })
      .finally(() => {
        pending = undefined;
      });
    return pending;
  }
  return { active, iface_stats, UPDATE_INFO };
});
