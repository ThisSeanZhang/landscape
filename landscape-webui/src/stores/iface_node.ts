import { ifaces } from "@/api/network";
import { get_iface_server_status } from "@/api/service_ipconfig";
import { NetDev } from "@/lib/dev";
import { ZoneType } from "@/lib/service_ipconfig";
import { defineStore } from "pinia";
import { ref, watch } from "vue";

export const useIfaceNodeStore = defineStore("iface_node", () => {
  const net_devs = ref<NetDev[]>([]);

  const nodes = ref<any>([]);
  const edges = ref<any>([]);

  const bridges = ref<any>([]);
  const eths = ref<any>([]);

  const node_call_back = ref<any>();

  watch(net_devs, async (new_value, _old_value) => {
    const tmp_nodes: any[] = [];
    const tmp_edges: any[] = [];
    const new_bridges: any[] = [];
    const new_eths: any[] = [];
    let wan_y = 0;
    let right_y = 0;
    let left_y = 0;
    for (const each of new_value) {
      if (each.dev_type === "Loopback") {
        continue;
      }

      if (each.dev_kind === "Bridge") {
        new_bridges.push({
          label: each.name,
          value: each.name,
          ifindex: each.index,
        });
      } else {
        if (each.zone_type !== ZoneType.Wan) {
          new_eths.push({
            label: each.name,
            value: each.name,
            ifindex: each.index,
          });
        }
      }
      let position = { x: 600, y: 100 };
      if (each.zone_type == ZoneType.Wan) {
        position.x = position.x - 300;
        position.y = position.y + wan_y;
        wan_y += 120;
      } else if (each.controller_id == undefined) {
        position.y = position.y + left_y;
        left_y += 120;
      } else {
        position.x = position.x + 400;
        position.y = position.y + right_y;
        right_y += 120;
      }
      tmp_nodes.push({
        id: `${each.index}`,
        data: each,
        type: "netflow",
        label: each.name,
        position,
      });
      if (each.controller_id != undefined) {
        tmp_edges.push({
          id: `${each.controller_id}-${each.index}`,
          source: `${each.controller_id}`,
          target: `${each.index}`,
          label: "",
          animated: true,
          // type: 'smoothstep',
          class: "normal-edge",
        });
      }
    }
    bridges.value = new_bridges;
    eths.value = new_eths;
    // console.log(nodes.value);

    nodes.value = tmp_nodes;
    edges.value = tmp_edges;

    if (node_call_back.value != undefined) {
      node_call_back.value();
    }
  });

  async function UPDATE_INFO() {
    net_devs.value = await ifaces();
  }

  async function SETTING_CALL_BACK(call_back: any) {
    node_call_back.value = call_back;
  }

  function FIND_BRIDGE_BY_IFINDEX(ifindex: any): boolean {
    for (const bridge of bridges.value) {
      if (bridge.ifindex == ifindex) {
        return true;
      }
    }
    return false;
  }

  function FIND_DEV_BY_IFINDEX(ifindex: any): NetDev | undefined {
    for (const dev of net_devs.value) {
      if (dev.index == ifindex) {
        return dev;
      }
    }
    return undefined;
  }

  return {
    nodes,
    edges,
    bridges,
    eths,
    UPDATE_INFO,
    SETTING_CALL_BACK,
    FIND_DEV_BY_IFINDEX,
    FIND_BRIDGE_BY_IFINDEX,
  };
});
