import type {
  FlowMatchRequest,
  FlowMatchResult,
  FlowVerdictResult,
  FlowVerdictRequest,
} from "@landscape-router/types/api/schemas";
import {
  traceFlowMatch,
  traceVerdict,
} from "@landscape-router/types/api/route/route";

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
