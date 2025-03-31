import { NetDev } from "@/lib/dev";
import { LandscapeDockerNetwork } from "@/lib/docker/network";

export function gen_default_router_node() {}

// 渲染节点的类型
export enum FlowNodeType {
  Dev = "netflow",
  Route = "router",
  Docker = "docker",
}

export type NodeData =
  | { t: FlowNodeType.Dev; dev: NetDev }
  | { t: FlowNodeType.Route; data: any }
  | {
      t: FlowNodeType.Docker;
      dev: NetDev;
      docker_info: LandscapeDockerNetwork;
    };

export type LandscapeNodePosition = { x: number; y: number };
export class LandscapeFlowNode {
  // 新的 ID 换为了网卡名称
  id: string;
  // 节点展示名称
  label: string;
  // 在拓扑图中的位置
  position: LandscapeNodePosition;
  // 节点数据信息
  data: NodeData;

  constructor(obj: {
    id: string;
    label: string;
    position: LandscapeNodePosition;
    data: NodeData;
  }) {
    this.id = obj.id;
    // this.type = obj.data.t;
    this.label = obj.label;
    this.position = obj.position;
    this.data = obj.data;
  }

  get type(): FlowNodeType {
    return this.data.t;
  }

  create_edge = (): LandscapeFlowEdge | undefined => {
    if (this.data.t === FlowNodeType.Dev) {
      if (
        this.data.dev.controller_name !== undefined &&
        this.data.dev.controller_name !== null
      ) {
        return new LandscapeFlowEdge({
          source: `${this.data.dev.controller_name}`,
          target: `${this.data.dev.name}`,
          label: "",
          animated: true,
          // type: 'smoothstep',
          class: undefined,
        });
      }
    }
    return undefined;
  };

  has_target_hook = (): boolean => {
    // if (this.zone_type == ZoneType.Wan) {
    //   return false;
    // } else if (this.zone_type == ZoneType.Lan) {
    //   return false;
    // } else if (this.zone_type == ZoneType.Undefined) {
    //   return true;
    // }
    return true;
  };

  // right Handle
  has_source_hook = (): boolean => {
    // if (this.zone_type == ZoneType.Wan) {
    //   return false;
    // } else if (this.dev_kind == "Bridge") {
    //   return true;
    // } else if (this.zone_type == ZoneType.Lan) {
    //   return true;
    // } else if (this.zone_type == ZoneType.Undefined) {
    //   return false;
    // }
    return true;
  };
}

export class LandscapeFlowEdge {
  // node_id1-node_id2
  id: string;
  // 源
  source: string;
  // 目标
  target: string;
  //
  label: string | undefined;
  // 动画
  animated: boolean;
  type: string | undefined;
  class: string | undefined;

  constructor(obj: {
    source: string;
    target: string;
    type?: string;
    label?: string;
    animated: boolean;
    class?: string;
  }) {
    this.id = `${obj.source}:${obj.target}`;
    this.source = obj.source;
    this.target = obj.target;
    this.label = obj.label;
    this.animated = obj.animated ?? true;
    this.type = obj.type;
    this.class = obj.class;
  }
}

export enum NodePositionType {
  Wan = "wan",
  Route = "router",
  Lan = "lan",
  Other = "other",
  WifiAp = "ap",
  Client = "client",
}

export class PosotionCalculator {
  wan: number;
  lan: number;
  lan_port: number;
  client: number;

  constructor() {
    this.wan = 0;
    this.lan = 0;
    this.lan_port = 0;
    this.client = 0;
  }

  get_position(node: LandscapeFlowNode) {
    if (node.data.t === FlowNodeType.Dev) {
      switch (node.data.dev.get_topology_type()) {
        case NodePositionType.Wan: {
          node.position.x = 100;
          node.position.y = this.wan;
          this.wan += 140;
          break;
        }
        case NodePositionType.Route: {
          node.position.x = 400;
          node.position.y = 500;
          break;
        }
        case NodePositionType.Lan: {
          node.position.x = 700;
          node.position.y = this.lan;
          this.lan += 120;
          break;
        }
        case NodePositionType.Other: {
          node.position.x = 1000;
          node.position.y = this.lan_port;
          this.lan_port += 120;
          break;
        }
        case NodePositionType.WifiAp: {
          node.position.x = 1000;
          node.position.y = this.lan_port;
          this.lan_port += 120;
          break;
        }
        case NodePositionType.Client: {
          node.position.x = 1300;
          node.position.y = this.client;
          this.client += 100;
          break;
        }
      }
    } else if (node.data.t === FlowNodeType.Docker) {
      node.position.x = 700;
      node.position.y = this.lan;
      this.lan += 120;
    }
  }
}
