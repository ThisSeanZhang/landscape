import type { FlowWanStatus } from "@landscape-router/types/api/schemas";

export function flowWanPresentation(statuses: FlowWanStatus[], flowId: number) {
  const rows = statuses.filter((row) => row.flow_id === flowId);
  return {
    // Cleanup describes the shared host policy, so report it once per card.
    cleanup: rows.find((row) => row.router_policy_cleanup),
    wanRows: rows.filter(
      (row) =>
        !row.router_policy_cleanup ||
        row.active_link_id != null ||
        row.candidates.length > 0 ||
        row.history.length > 0,
    ),
  };
}
