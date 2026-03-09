import {
  listGatewayRules,
  createGatewayRule,
  getGatewayRule,
  deleteGatewayRule,
  getGatewayStatus,
} from "@landscape-router/types/api/gateway/gateway";
import type {
  HttpUpstreamRuleConfig,
  GatewayStatus,
} from "@landscape-router/types/api/schemas";

export async function get_gateway_rules(): Promise<HttpUpstreamRuleConfig[]> {
  return listGatewayRules();
}

export async function get_gateway_rule(
  id: string,
): Promise<HttpUpstreamRuleConfig> {
  return getGatewayRule(id);
}

export async function push_gateway_rule(
  rule: HttpUpstreamRuleConfig,
): Promise<void> {
  await createGatewayRule(rule);
}

export async function delete_gateway_rule(id: string): Promise<void> {
  await deleteGatewayRule(id);
}

export async function get_gateway_status(): Promise<GatewayStatus> {
  return getGatewayStatus();
}
