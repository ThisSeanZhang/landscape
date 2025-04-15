import { FlowConfig } from "@/rust_bindings/flow";

export function flow_config_default(): FlowConfig {
  return {
    enable: true,
    flow_id: -1,
    flow_match_rules: [],
    packet_handle_iface_name: [],
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

export enum FlowDnsMarkType {
  KeepGoing = "keepgoing",
  Direct = "direct",
  Drop = "drop",
  Redirect = "redirect",
  AllowReusePort = "allowreuseport",
}
