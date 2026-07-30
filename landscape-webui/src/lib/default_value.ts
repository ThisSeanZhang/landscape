import type { FlowConfig } from "@landscape-router/types/api/schemas";
import i18n from "@/i18n";

export function flow_config_default(): FlowConfig {
  return {
    enable: true,
    flow_id: -1,
    flow_match_rules: [],
    flow_targets: [],
    name: "",
    remark: "",
  };
}

export enum FlowTargetTypes {
  INTERFACE = "interface",
  NETNS = "netns",
}

export function flow_target_options(): { label: string; value: string }[] {
  const { t } = i18n.global;
  return [
    {
      label: t("flow.target_rule.type_interface"),
      value: FlowTargetTypes.INTERFACE,
    },
    {
      label: t("flow.target_rule.type_netns"),
      value: FlowTargetTypes.NETNS,
    },
  ];
}

export enum FlowMarkType {
  KeepGoing = "keep_going",
  Direct = "direct",
  Drop = "drop",
  Redirect = "redirect",
}
