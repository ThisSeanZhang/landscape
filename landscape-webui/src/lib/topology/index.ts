import { NetDev } from "@/lib/dev";
import { LandscapeDockerNetwork } from "@/lib/docker/network";
import { IfaceInfo, RawIfaceInfo } from "landscape-types/common/iface";
import { ZoneType } from "../service_ipconfig";

export function gen_default_router_node() {}

// 渲染节点的类型
export enum FlowNodeType {
  // Dev = "netflow",
  // Route = "router",
  // Docker = "docker",
  Managed = "managed",
  UnManaged = "unmanaged",
  ManagedDocker = "managed-docker",
  UnManagedDocker = "unmanaged-docker",
  DockerLeaf = "docker-leaf",
}

export type NodeData =
  // | { t: FlowNodeType.Dev; dev: NetDev }
  // | { t: FlowNodeType.Route; data: any }
  // | {
  //     t: FlowNodeType.Docker;
  //     dev: NetDev;
  //     docker_info: LandscapeDockerNetwork;
  //   }
  | {
      t: FlowNodeType.Managed;
      dev: IfaceInfo;
    }
  | {
      t: FlowNodeType.UnManaged;
      dev: RawIfaceInfo;
    }
  | {
      t: FlowNodeType.ManagedDocker;
      dev: IfaceInfo;
      docker_data: LandscapeDockerNetwork;
    }
  | {
      t: FlowNodeType.UnManagedDocker;
      dev: RawIfaceInfo;
      docker_data: LandscapeDockerNetwork;
    }
  | {
      t: FlowNodeType.DockerLeaf;
      dev: RawIfaceInfo;
    };

export type LandscapeNodePosition = { x: number; y: number };
export class LandscapeFlowNode {
  // 新的 ID 使用网卡名称
  id: string;
  // 节点展示名称
  label: string;
  // 在拓扑图中的位置
  position: LandscapeNodePosition;
  parent: string | null;
  // 节点数据信息
  data: NodeData;

  constructor(obj: {
    id: string;
    label: string;
    parent?: string | null;
    position: LandscapeNodePosition;
    data: NodeData;
  }) {
    this.id = obj.id;
    // this.type = obj.data.t;
    this.label = obj.label;
    this.position = obj.position;
    this.data = obj.data;
    this.parent = obj.parent ?? null;
  }

  get type(): FlowNodeType {
    return this.data.t;
  }

  create_edge = (): LandscapeFlowEdge | undefined => {
    if (this.parent !== null && this.parent !== undefined) {
      return new LandscapeFlowEdge({
        source: `${this.parent}`,
        target: `${this.id}`,
        label: "",
        animated: true,
        // type: 'smoothstep',
        class: undefined,
      });
    }
    // if (this.data.t === FlowNodeType.Dev) {
    //   if (
    //     this.data.dev.controller_name !== undefined &&
    //     this.data.dev.controller_name !== null
    //   ) {
    //     return new LandscapeFlowEdge({
    //       source: `${this.data.dev.controller_name}`,
    //       target: `${this.data.dev.name}`,
    //       label: "",
    //       animated: true,
    //       // type: 'smoothstep',
    //       class: undefined,
    //     });
    //   }
    // }

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
  InnerClient = "client",
  Client = "client",
}

const XPosotion = {
  WAN: 100,
  Route: 400,
  Lan: 700,
  Other: 1000,
  WifiAp: 1000,
  InnerClient: 1000,
  Client: 1300,
} as const;

function get_position(data: IfaceInfo | RawIfaceInfo, node_type: FlowNodeType) {
  if ("config" in data) {
    if (data.config.zone_type === ZoneType.Wan) {
      return NodePositionType.Wan;
    } else {
      return NodePositionType.Lan;
    }
  } else {
    switch (node_type) {
      // case FlowNodeType.Dev:
      // case FlowNodeType.Route:
      // case FlowNodeType.Docker:
      case FlowNodeType.Managed:
        return NodePositionType.Lan;
      case FlowNodeType.UnManaged:
        return NodePositionType.Lan;
      case FlowNodeType.ManagedDocker:
        return NodePositionType.Lan;
      case FlowNodeType.UnManagedDocker:
        return NodePositionType.Lan;
      case FlowNodeType.DockerLeaf:
        return NodePositionType.Client;
      default:
        return NodePositionType.Other;
    }
  }
}
export class PosotionCalculator {
  wan: number;
  lan: number;
  lan_port: number;
  client: number;

  // 位置缓存获取函数
  private get_cached_position: (
    nodeId: string,
  ) => { x: number; y: number } | null;
  // 位置保存函数
  private save_position: (
    nodeId: string,
    position: { x: number; y: number },
  ) => void;

  constructor(
    get_cached_position?: (nodeId: string) => { x: number; y: number } | null,
    save_position?: (
      nodeId: string,
      position: { x: number; y: number },
    ) => void,
  ) {
    this.wan = 0;
    this.lan = 0;
    this.lan_port = 0;
    this.client = 0;
    this.get_cached_position = get_cached_position || (() => null);
    this.save_position = save_position || (() => {});
  }

  get_position(node: LandscapeFlowNode) {
    // 检查是否有缓存的位置 - 优先使用缓存
    const cached = this.get_cached_position(node.id);
    if (cached) {
      node.position.x = cached.x;
      node.position.y = cached.y;
      return;
    }

    // 如果有父节点，使用默认的父子布局
    if (node.parent) {
      node.position.x = XPosotion.InnerClient;
      node.position.y = this.client;
      this.client += 100;
    } else {
      // 根据节点类型设置默认位置
      switch (get_position(node.data.dev, node.data.t)) {
        case NodePositionType.Wan: {
          node.position.x = XPosotion.WAN;
          node.position.y = this.wan;
          this.wan += 140;
          break;
        }
        // case NodePositionType.Route: {
        //   node.position.x = XPosotion.Route;
        //   node.position.y = 500;
        //   break;
        // }
        case NodePositionType.Lan: {
          node.position.x = XPosotion.Lan;
          node.position.y = this.lan;
          this.lan += 120;
          break;
        }
        case NodePositionType.Other: {
          node.position.x = XPosotion.Other;
          node.position.y = this.lan_port;
          this.lan_port += 120;
          break;
        }
        // case NodePositionType.WifiAp: {
        //   node.position.x = XPosotion.WifiAp;
        //   node.position.y = this.lan_port;
        //   this.lan_port += 120;
        //   break;
        // }
        case NodePositionType.Client: {
          node.position.x = XPosotion.Client;
          node.position.y = this.client;
          this.client += 100;
          break;
        }
      }
    }

    // 保存计算出的默认位置到缓存
    this.save_position(node.id, { x: node.position.x, y: node.position.y });
  }
}
