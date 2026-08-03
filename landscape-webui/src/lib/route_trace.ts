import { isIPv4, isIPv6 } from "is-ip";
import type {
  FlowMatchResult,
  FlowVerdictRequest,
  FlowVerdictResult,
  SingleVerdictResult,
} from "@landscape-router/types/api/schemas";

export type TraceIpFamily = "ipv4" | "ipv6";

export interface TraceSourceAddresses {
  ipv4?: string;
  ipv6?: string;
}

export interface VerdictBatch {
  family: TraceIpFamily;
  indices: number[];
  request: FlowVerdictRequest;
}

export interface VerdictPlan {
  batches: VerdictBatch[];
  invalidIps: string[];
}

export interface VerdictBatchResult {
  batch: VerdictBatch;
  result: FlowVerdictResult;
}

export function flowIdForFamily(
  matchResult: FlowMatchResult,
  family: TraceIpFamily,
): number {
  return family === "ipv4"
    ? matchResult.effective_flow_id_v4
    : matchResult.effective_flow_id_v6;
}

export function buildVerdictPlan(
  matchResult: FlowMatchResult,
  source: TraceSourceAddresses,
  ips: string[],
): VerdictPlan {
  const entries: Record<TraceIpFamily, Array<{ ip: string; index: number }>> = {
    ipv4: [],
    ipv6: [],
  };
  const invalidIps: string[] = [];

  ips.forEach((ip, index) => {
    if (isIPv4(ip)) {
      entries.ipv4.push({ ip, index });
    } else if (isIPv6(ip)) {
      entries.ipv6.push({ ip, index });
    } else {
      invalidIps.push(ip);
    }
  });

  const batches: VerdictBatch[] = [];
  if (entries.ipv4.length > 0) {
    batches.push({
      family: "ipv4",
      indices: entries.ipv4.map(({ index }) => index),
      request: {
        flow_id: flowIdForFamily(matchResult, "ipv4"),
        src_ipv4: source.ipv4 || undefined,
        dst_ips: entries.ipv4.map(({ ip }) => ip),
      },
    });
  }
  if (entries.ipv6.length > 0) {
    batches.push({
      family: "ipv6",
      indices: entries.ipv6.map(({ index }) => index),
      request: {
        flow_id: flowIdForFamily(matchResult, "ipv6"),
        src_ipv6: source.ipv6 || undefined,
        dst_ips: entries.ipv6.map(({ ip }) => ip),
      },
    });
  }

  return { batches, invalidIps };
}

export function mergeVerdictBatchResults(
  totalCount: number,
  batchResults: VerdictBatchResult[],
): SingleVerdictResult[] {
  const merged: Array<SingleVerdictResult | undefined> = Array(totalCount);

  for (const { batch, result } of batchResults) {
    batch.indices.forEach((originalIndex, batchIndex) => {
      merged[originalIndex] = result.verdicts[batchIndex];
    });
  }

  return merged.filter(
    (verdict): verdict is SingleVerdictResult => verdict !== undefined,
  );
}
