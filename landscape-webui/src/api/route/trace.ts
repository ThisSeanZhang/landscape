import type {
  FlowMatchRequest,
  FlowVerdictRequest,
} from "@landscape-router/types/api/schemas";
import {
  traceFlowMatch,
  traceVerdict,
} from "@landscape-router/types/api/route/route";
import type {
  FlowMatchResult as FlowMatchResultType,
  FlowVerdictResult as FlowVerdictResultType,
} from "@landscape-router/types/api/schemas";

export type FlowMatchResult = FlowMatchResultType;
export type FlowVerdictResult = FlowVerdictResultType;

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
