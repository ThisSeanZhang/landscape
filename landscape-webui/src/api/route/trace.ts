import type {
  FlowMatchRequest,
  FlowVerdictRequest,
} from "landscape-types/api/schemas";
import { traceFlowMatch, traceVerdict } from "landscape-types/api/route/route";
import type {
  TraceFlowMatch200Data,
  TraceVerdict200Data,
} from "landscape-types/api/schemas";

export type FlowMatchResult = TraceFlowMatch200Data;
export type FlowVerdictResult = TraceVerdict200Data;

export async function trace_flow_match(
  req: FlowMatchRequest,
): Promise<FlowMatchResult> {
  return await traceFlowMatch(req);
}

export async function trace_verdict(
  req: FlowVerdictRequest,
): Promise<FlowVerdictResult> {
  return await traceVerdict(req);
}
