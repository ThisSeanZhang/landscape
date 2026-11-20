import { createFlowMark } from "./default_value";

import type { WanIpRuleConfig } from "@landscape-router/types/api/schemas";
export function createWanIpRule(
  obj: Partial<WanIpRuleConfig> = {},
): WanIpRuleConfig {
  return {
    id: obj?.id,
    name: obj?.name,
    index: obj?.index ?? -1,
    enable: obj?.enable ?? true,
    mark: createFlowMark(obj.mark),
    source: obj.source?.map((source) => ({ ...source })) ?? [],
    remark: obj?.remark ?? "",
    flow_id: obj?.flow_id ?? 0,
    override_dns: obj?.override_dns ?? false,
    update_at: obj?.update_at,
  };
}
