import {
  listGatewayRules,
  createGatewayRule,
  getGatewayRule,
  deleteGatewayRule,
  getGatewayStatus,
  restartGateway,
} from "@landscape-router/types/api/gateway/gateway";
import {
  getGatewayConfig,
  updateGatewayConfig,
} from "@landscape-router/types/api/system-config/system-config";
import type {
  GetGatewayConfigResponse,
  GatewayStatus,
  HttpUpstreamRuleConfig,
  UpdateGatewayConfigRequest,
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

export async function get_gateway_config_edit(): Promise<GetGatewayConfigResponse> {
  return getGatewayConfig();
}

export async function update_gateway_config(
  payload: UpdateGatewayConfigRequest,
): Promise<void> {
  await updateGatewayConfig(payload);
}

export async function restart_gateway(): Promise<GatewayStatus> {
  return restartGateway();
}
