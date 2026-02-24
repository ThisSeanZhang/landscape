import { convert_flow_mark, MarkType } from "./dns";

import type {
  FlowMark,
  WanIPRuleSource,
  WanIpRuleConfig,
} from "@landscape-router/types/api/schemas";
export class WanIpRuleConfigClass implements WanIpRuleConfig {
  id: string | null;
  index: number;
  enable: boolean;
  mark: FlowMark;
  source: WanIPRuleSource[];
  remark: string;
  flow_id: number;
  override_dns: boolean;
  update_at: number;

  constructor(obj: Partial<WanIpRuleConfig> = {}) {
    this.id = obj?.id ?? null;
    this.index = obj?.index ?? -1;
    this.enable = obj?.enable ?? true;
    this.mark = convert_flow_mark(obj.mark);
    this.source = obj?.source ? obj?.source.map(new_wan_rules) : [];
    this.remark = obj?.remark ?? "";
    this.flow_id = obj?.flow_id ?? 0;
    this.override_dns = obj?.override_dns ?? false;
    this.update_at = obj?.update_at ?? new Date().getTime();
  }
}

export function new_wan_rules(e: WanIPRuleSource): WanIPRuleSource {
  if (e.t == "config") {
    return { t: "config", ip: e.ip, prefix: e.prefix };
  } else {
    return {
      t: "geo_key",
      key: e.key,
      name: e.name,
      inverse: false,
      attribute_key: null,
    };
  }
}
