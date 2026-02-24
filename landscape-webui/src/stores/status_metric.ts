import { defineStore } from "pinia";
import { ref, computed } from "vue";
import {
  get_connects_info,
  get_metric_status,
  get_connect_metric_info,
  get_src_ip_stats,
  get_dst_ip_stats,
  get_connect_global_stats,
} from "@/api/metric";
import { ServiceStatus, ServiceStatusType } from "@/lib/services";
import type {
  ConnectKey,
  ConnectRealtimeStatus,
  IpRealtimeStat,
  ConnectGlobalStats,
} from "@landscape-router/types/api/schemas";

export const useMetricStore = defineStore("dns_metric", () => {
  const activeModes = ref(new Set<"live" | "src" | "dst">());
  const metric_status = ref<ServiceStatus>({ t: ServiceStatusType.Stop });
  const firewall_info = ref<ConnectRealtimeStatus[]>();
  const src_ip_stats = ref<IpRealtimeStat[]>([]);
  const dst_ip_stats = ref<IpRealtimeStat[]>([]);
  const global_history_stats = ref<ConnectGlobalStats | null>(null);

  const is_down = computed(() => {
    return metric_status.value.t == ServiceStatusType.Stop;
  });

  const is_enabled = computed(() => activeModes.value.size > 0);

  async function UPDATE_INFO() {
    if (is_enabled.value) {
      metric_status.value = await get_metric_status();

      const promises: Promise<any>[] = [];
      const modes = Array.from(activeModes.value);

      // Always fetch connects if 'live' is active, OR if src/dst is active (for filtration/aggregation)
      // But SrcIpMetric/DstIpMetric only need firewall_info if they have filters.
      // For simplicity, if ANY mode is active, we might need basic info.
      // However, we can be more precise:
      if (activeModes.value.has("live") || activeModes.value.size > 0) {
        promises.push(
          get_connects_info().then((res) => (firewall_info.value = res)),
        );
      }

      if (activeModes.value.has("src")) {
        promises.push(
          get_src_ip_stats().then((res) => (src_ip_stats.value = res)),
        );
      }

      if (activeModes.value.has("dst")) {
        promises.push(
          get_dst_ip_stats().then((res) => (dst_ip_stats.value = res)),
        );
      }

      await Promise.all(promises);
    }
  }

  async function UPDATE_GLOBAL_HISTORY_STATS() {
    global_history_stats.value = await get_connect_global_stats();
  }

  async function SET_ENABLE(mode: "live" | "src" | "dst", value: boolean) {
    if (value) {
      activeModes.value.add(mode);
    } else {
      activeModes.value.delete(mode);
    }
  }

  return {
    SET_ENABLE,
    is_down,
    metric_status,
    firewall_info,
    src_ip_stats,
    dst_ip_stats,
    global_history_stats,
    UPDATE_INFO,
    UPDATE_GLOBAL_HISTORY_STATS,
  };
});
