import { IfaceZoneType, WifiMode } from "@landscape-router/types/api/schemas";
import type {
  DeviceKind,
  DeviceType,
  DevState,
  IfaceTopology,
  LandscapeWifiInterface,
} from "@landscape-router/types/api/schemas";
import type { WanLink } from "@/lib/wan/wan_link";

type TopologyNodeInput = Partial<IfaceTopology> &
  Pick<
    IfaceTopology,
    | "name"
    | "index"
    | "dev_type"
    | "dev_status"
    | "carrier"
    | "zone_type"
    | "enable_in_boot"
  > & {
    virtual?: boolean;
    wan_link?: WanLink;
  };

export class NetDev {
  name: string;
  index: number;
  mac: string | undefined;
  perm_mac: string | undefined;
  dev_type: DeviceType;
  dev_kind: DeviceKind | undefined;
  dev_status: DevState;
  controller_name: string | undefined;
  controller_id: number | undefined;
  carrier: boolean;
  zone_type: IfaceZoneType;
  enable_in_boot: boolean;

  netns_id: number | undefined;
  peer_link_id: number | undefined;

  wifi_info: LandscapeWifiInterface | undefined;
  wifi_mode: WifiMode | undefined;

  /** pppd-type WAN link backing this (virtual or live) ppp card. */
  wan_link: WanLink | undefined;
  virtual: boolean;

  constructor(obj: TopologyNodeInput) {
    this.name = obj.name;
    this.index = obj.index;
    this.mac = obj.mac;
    this.perm_mac = obj.perm_mac;
    this.dev_type = obj.dev_type;
    this.dev_kind = obj.dev_kind;
    this.dev_status = { ...obj.dev_status };

    const controller_id = obj.controller_id ?? undefined;
    this.controller_id = controller_id;
    this.controller_name =
      controller_id !== undefined
        ? (obj.controller_name ?? undefined)
        : undefined;

    this.carrier = obj.carrier;
    this.zone_type = obj.zone_type;
    this.enable_in_boot = obj.enable_in_boot;
    this.netns_id = obj.netns_id;
    this.peer_link_id = obj.peer_link_id;
    this.wifi_info =
      obj.wifi_info == null
        ? undefined
        : {
            name: obj.wifi_info.name ?? "",
            index: obj.wifi_info.index ?? 0,
            wifi_type: obj.wifi_info.wifi_type ?? { t: "Unspecified" },
          };
    this.wifi_mode = obj.wifi_mode ?? WifiMode.undefined;
    this.wan_link = obj.wan_link;
    this.virtual = obj.virtual ?? false;
  }
  // left Handle
  has_target_hook() {
    if (this.virtual) {
      return false;
    }
    if (this.dev_kind == "bridge") {
      return false;
    }

    if (this.zone_type == IfaceZoneType.wan) {
      return false;
    } else if (this.zone_type == IfaceZoneType.lan) {
      return false;
    } else if (this.zone_type == IfaceZoneType.undefined) {
      return true;
    }
  }

  // right Handle
  has_source_hook() {
    if (this.dev_kind == "bridge") {
      return true;
    }

    return false;
  }
}
