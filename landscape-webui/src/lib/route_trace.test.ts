import { describe, expect, it } from "vitest";
import type {
  FlowMatchResult,
  SingleVerdictResult,
} from "@landscape-router/types/api/schemas";
import {
  buildVerdictPlan,
  flowIdForFamily,
  mergeVerdictBatchResults,
} from "@/lib/route_trace";

const matchResult: FlowMatchResult = {
  effective_flow_id: 4,
  effective_flow_id_v4: 4,
  effective_flow_id_v6: 9,
  flow_id_by_ipv4: 4,
  flow_id_by_ipv6: 9,
};

function verdict(dstIp: string): SingleVerdictResult {
  return {
    cache_consistent: true,
    dst_ip: dstIp,
    effective_mark: {
      action: { t: "keep_going" },
      allow_reuse_port: false,
      flow_id: 0,
    },
    expected_cache_mark: 0,
    has_cache: false,
  };
}

describe("route trace verdict planning", () => {
  it("selects the effective flow for each address family", () => {
    expect(flowIdForFamily(matchResult, "ipv4")).toBe(4);
    expect(flowIdForFamily(matchResult, "ipv6")).toBe(9);
  });

  it("builds separate IPv4 and IPv6 requests", () => {
    const plan = buildVerdictPlan(
      matchResult,
      { ipv4: "192.0.2.10", ipv6: "2001:db8::10" },
      ["2001:db8::20", "198.51.100.20", "2001:db8::30"],
    );

    expect(plan.invalidIps).toEqual([]);
    expect(plan.batches).toEqual([
      {
        family: "ipv4",
        indices: [1],
        request: {
          flow_id: 4,
          src_ipv4: "192.0.2.10",
          dst_ips: ["198.51.100.20"],
        },
      },
      {
        family: "ipv6",
        indices: [0, 2],
        request: {
          flow_id: 9,
          src_ipv6: "2001:db8::10",
          dst_ips: ["2001:db8::20", "2001:db8::30"],
        },
      },
    ]);
  });

  it("rejects malformed IP addresses", () => {
    const plan = buildVerdictPlan(matchResult, {}, [
      "192.0.2.1",
      ":::",
      "1:2:3:4:5:6:7:8:9",
    ]);

    expect(plan.invalidIps).toEqual([":::", "1:2:3:4:5:6:7:8:9"]);
    expect(plan.batches).toHaveLength(1);
  });

  it("restores mixed-family results to their original order", () => {
    const ips = ["2001:db8::20", "198.51.100.20", "2001:db8::20"];
    const plan = buildVerdictPlan(matchResult, {}, ips);
    const ipv4Batch = plan.batches.find((batch) => batch.family === "ipv4")!;
    const ipv6Batch = plan.batches.find((batch) => batch.family === "ipv6")!;

    const merged = mergeVerdictBatchResults(ips.length, [
      { batch: ipv4Batch, result: { verdicts: [verdict("198.51.100.20")] } },
      {
        batch: ipv6Batch,
        result: {
          verdicts: [verdict("2001:db8::20"), verdict("2001:db8::20")],
        },
      },
    ]);

    expect(merged.map(({ dst_ip }) => dst_ip)).toEqual(ips);
  });
});
