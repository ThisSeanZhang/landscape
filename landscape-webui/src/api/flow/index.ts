import {
  getFlowRules,
  getFlowRule,
  getFlowRuleByFlowId,
  addFlowRule,
  delFlowRule,
} from "@landscape-router/types/api/flow-rules/flow-rules";
import type { FlowConfig } from "@landscape-router/types/api/schemas";

export async function get_flow_rules(): Promise<FlowConfig[]> {
  return getFlowRules();
}

export async function get_flow_rule(id: string): Promise<FlowConfig> {
  return getFlowRule(id);
}

export async function get_flow_rule_by_flow_id(
  id: number,
): Promise<FlowConfig> {
  return getFlowRuleByFlowId(id);
}

export async function push_flow_rules(config: FlowConfig): Promise<void> {
  await addFlowRule(config);
}

export async function del_flow_rules(id: string): Promise<void> {
  await delFlowRule(id);
}
