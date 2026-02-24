import type { FlowConfig } from "@landscape-router/types/api/schemas";

export function flow_config_default(): FlowConfig {
  return {
    enable: true,
    flow_id: -1,
    flow_match_rules: [],
    flow_targets: [],
    remark: "",
  };
}

export enum FlowTargetTypes {
  INTERFACE = "interface",
  NETNS = "netns",
}

export function flow_target_options(): { label: string; value: string }[] {
  return [
    {
      label: "网卡",
      value: FlowTargetTypes.INTERFACE,
    },
    {
      label: "Docker 容器名称",
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
