import { onScopeDispose, ref } from "vue";
import {
  get_history_dst_ip_stats,
  get_history_src_ip_stats,
} from "@/api/metric";
import type {
  GetHistorySrcIpStatsParams,
  IpHistoryStat,
} from "@landscape-router/types/api/schemas";

type Filters = Omit<
  GetHistorySrcIpStatsParams,
  "src_ip" | "dst_ip" | "flow_id"
> & {
  ip: string;
  flowId: number | null;
};

export function useHistoryIpStats(direction: "src" | "dst") {
  const stats = ref<IpHistoryStat[]>([]);
  const loading = ref(false);
  let latestRequest = 0;
  onScopeDispose(() => {
    latestRequest++;
  });

  async function query({ ip, flowId, ...filters }: Filters) {
    const request = ++latestRequest;
    const params = { ...filters, flow_id: flowId ?? undefined };
    loading.value = true;
    try {
      const result =
        direction === "src"
          ? await get_history_src_ip_stats({
              ...params,
              src_ip: ip || undefined,
            })
          : await get_history_dst_ip_stats({
              ...params,
              dst_ip: ip || undefined,
            });
      if (request === latestRequest) stats.value = result;
    } finally {
      if (request === latestRequest) loading.value = false;
    }
  }

  return { stats, loading, query };
}
