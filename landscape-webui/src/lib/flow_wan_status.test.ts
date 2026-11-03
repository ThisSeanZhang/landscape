import type { FlowWanStatus } from "@landscape-router/types/api/schemas";
import { describe, expect, it } from "vitest";
import { flowWanPresentation } from "./flow_wan_status";

function status(overrides: Partial<FlowWanStatus> = {}): FlowWanStatus {
  return {
    flow_id: 0,
    ipv6: false,
    automatic: true,
    active_link_id: "wan-a",
    active_iface_name: "wan-a",
    reason: "healthy",
    selected_at_ms: 1,
    retry_after_secs: null,
    candidates: [
      {
        link_id: "wan-a",
        iface_name: "wan-a",
        route_available: true,
        health: "healthy",
      },
    ],
    history: [],
    router_policy_applied: true,
    router_policy_error: null,
    router_policy_checked_at_ms: 1,
    router_policy_cleanup: false,
    ...overrides,
  };
}

describe("flow WAN presentation", () => {
  it("keeps dual-stack WAN state and history while host policy cleanup fails", () => {
    const v4 = status({
      router_policy_cleanup: true,
      router_policy_applied: false,
      router_policy_error: "-6: policy cleanup failed",
      history: [
        {
          at_ms: 1,
          previous: "wan-b",
          active: "wan-a",
          reason: "healthy",
          cause: "recovery",
          connection_policy: "new_connections_only",
        },
      ],
    });
    const v6 = status({ ...v4, ipv6: true });
    const view = flowWanPresentation([v4, v6], 0);
    expect(view.wanRows).toEqual([v4, v6]);
    expect(view.wanRows[0].history).toHaveLength(1);
    expect(view.cleanup?.router_policy_error).toBe("-6: policy cleanup failed");
  });

  it("shows one cleanup notice without fake WAN exits after owner deletion", () => {
    const cleanup = status({
      automatic: false,
      active_link_id: null,
      active_iface_name: null,
      reason: "no_available_wan",
      candidates: [],
      router_policy_cleanup: true,
      router_policy_applied: false,
    });
    const view = flowWanPresentation(
      [cleanup, status({ ...cleanup, ipv6: true })],
      0,
    );
    expect(view.wanRows).toEqual([]);
    expect(view.cleanup).toBe(cleanup);
  });

  it("keeps ordinary state and isolates another flow's cleanup notice", () => {
    const v4 = status({ flow_id: 9 });
    const v6 = status({ flow_id: 9, ipv6: true });
    const view = flowWanPresentation(
      [status({ router_policy_cleanup: true }), v4, v6],
      9,
    );
    expect(view.wanRows).toEqual([v4, v6]);
    expect(view.cleanup).toBeUndefined();
  });
});
