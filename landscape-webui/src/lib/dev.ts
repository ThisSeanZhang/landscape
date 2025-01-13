import { ZoneType } from "./service_ipconfig";

export class NetDev {
  name: string;
  index: number;
  mac: string | undefined;
  perm_mac: string | undefined;
  dev_type: string;
  dev_kind: string;
  dev_status: DevState;
  controller: string | undefined;
  controller_id: number | undefined;
  carrier: boolean;
  zone_type: ZoneType;
  enable_in_boot: boolean;

  netns_id: number | undefined;
  peer_link_id: number | undefined;

  constructor(obj: any) {
    this.name = obj.name;
    this.index = obj.index;
    this.mac = obj.mac;
    this.perm_mac = obj.perm_mac;
    this.dev_type = obj.dev_type;
    this.dev_kind = obj.dev_kind;
    this.dev_status = { ...obj.dev_status };
    this.controller = obj.controller;
    this.controller_id = obj.controller_id;
    this.carrier = obj.carrier;
    this.zone_type = obj.zone_type;
    this.enable_in_boot = obj.enable_in_boot;
    this.netns_id = obj.netns_id;
    this.peer_link_id = obj.peer_link_id;
  }
  // left Handle
  has_target_hook() {
    if (this.zone_type == ZoneType.Wan) {
      return false;
    } else if (this.zone_type == ZoneType.Lan) {
      return false;
    } else if (this.zone_type == ZoneType.Undefined) {
      return true;
    }
  }

  // right Handle
  has_source_hook() {
    if (this.zone_type == ZoneType.Wan) {
      return false;
    } else if (this.dev_kind == "Bridge") {
      return true;
    } else if (this.zone_type == ZoneType.Lan) {
      return true;
    } else if (this.zone_type == ZoneType.Undefined) {
      return false;
    }
  }
}

export function filter(array: Array<any>): Map<number, Array<any>> {
  const a = new Map();
  // before
  for (let i = 0; i < array.length; i++) {
    let c = new NetDev(array[i]);
    let index = 0;
    if (c.controller_id != undefined) {
      index = c.controller_id;
      console.log(c);
    } else {
    }
    let arr = a.get(index);
    if (arr) {
      arr.push(c);
    } else {
      a.set(index, [c]);
    }
  }
  return a;
}

// 定义一个单独的枚举类型，用来表示变体的标签 `t`
export enum DevStateType {
  Unknown = "Unknown",
  NotPresent = "NotPresent",
  Down = "Down",
  LowerLayerDown = "LowerLayerDown",
  Testing = "Testing",
  Dormant = "Dormant",
  Up = "Up",
  Other = "Other",
}

// 定义 DevState 类型，使用 DevStateType 来表示 `t` 字段
export type DevState =
  | { t: DevStateType.Unknown }
  | { t: DevStateType.NotPresent }
  | { t: DevStateType.Down }
  | { t: DevStateType.LowerLayerDown }
  | { t: DevStateType.Testing }
  | { t: DevStateType.Dormant }
  | { t: DevStateType.Up }
  | { t: DevStateType.Other; c: number }; // 仅 "Other" 类型有额外字段 c
