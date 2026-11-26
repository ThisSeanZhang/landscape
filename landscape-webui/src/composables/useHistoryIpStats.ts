import { ref } from "vue";
import { useLatestHistoryQuery } from "./useLatestHistoryQuery";
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
  const { loading, failed, hasResult, run, invalidate } =
    useLatestHistoryQuery();

  function query({ ip, flowId, ...filters }: Filters) {
    const params = { ...filters, flow_id: flowId ?? undefined };
    return run(
      () =>
        direction === "src"
          ? get_history_src_ip_stats({ ...params, src_ip: ip || undefined })
          : get_history_dst_ip_stats({ ...params, dst_ip: ip || undefined }),
      (result) => {
        stats.value = result;
      },
    );
  }

  return { stats, loading, failed, hasResult, query, invalidate };
}
