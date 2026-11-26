import { effectScope } from "vue";
import { expect, it, vi } from "vitest";
import {
  get_history_dst_ip_stats,
  get_history_src_ip_stats,
} from "@/api/metric";
import type { IpHistoryStat } from "@landscape-router/types/api/schemas";
import { useHistoryIpStats } from "./useHistoryIpStats";

vi.mock("@/api/metric", () => ({
  get_history_src_ip_stats: vi.fn(),
  get_history_dst_ip_stats: vi.fn(),
}));

it.each(["src", "dst"] as const)(
  "preserves default flow 0 for %s and omits the all-flows filter",
  async (direction) => {
    const scope = effectScope();
    const view = scope.run(() => useHistoryIpStats(direction))!;
    const api = vi.mocked(
      direction === "src" ? get_history_src_ip_stats : get_history_dst_ip_stats,
    );
    api.mockResolvedValue([]);
    await view.query({ flowId: 0, ip: "192.0.2.1" });
    expect(api).toHaveBeenLastCalledWith({
      flow_id: 0,
      [direction + "_ip"]: "192.0.2.1",
    });
    await view.query({ flowId: null, ip: "" });
    expect(api).toHaveBeenLastCalledWith({
      flow_id: undefined,
      [direction + "_ip"]: undefined,
    });
    scope.stop();
  },
);

it("only the latest request can publish rows or end the loading state", async () => {
  const scope = effectScope();
  const view = scope.run(() => useHistoryIpStats("src"))!;
  const pending: ((rows: IpHistoryStat[]) => void)[] = [];
  vi.mocked(get_history_src_ip_stats).mockImplementation(
    () => new Promise((resolve) => pending.push(resolve)),
  );
  const requests = [1, 2, 3].map((flowId) => view.query({ flowId, ip: "" }));
  pending[1]([]);
  await requests[1];
  expect(view.loading.value).toBe(true);
  const latest = [
    {
      ip: "192.0.2.3",
      flow_id: 3,
      connect_count: 1,
      total_egress_bytes: 0,
      total_ingress_bytes: 0,
      total_ingress_pkts: 0,
      total_egress_pkts: 0,
    },
  ];
  pending[2](latest);
  await requests[2];
  expect(view.loading.value).toBe(false);
  pending[0]([]);
  await requests[0];
  expect(view.stats.value).toEqual(latest);
  scope.stop();
});
