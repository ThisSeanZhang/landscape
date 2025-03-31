import { computed, ref, watch } from "vue";
import { defineStore } from "pinia";
import { useVueFlow, type Edge, type Node } from "@vue-flow/core";
import {
  FlowNodeType,
  LandscapeFlowEdge,
  LandscapeFlowNode,
  PosotionCalculator,
} from "@/lib/flow";
import { DevStateType, NetDev } from "@/lib/dev";
import { ifaces } from "@/api/network";
import { get_all_docker_networks } from "@/api/docker/network";
import { LandscapeDockerNetwork } from "@/lib/docker/network";
import { UnfoldLessFilled } from "@vicons/material";

export const useTopologyStore = defineStore("topology", () => {
  const nodes = ref<LandscapeFlowNode[]>([]);
  const devs = ref<NetDev[]>([]);

  const topo_nodes = ref<LandscapeFlowNode[]>([]);
  const topo_edges = ref<LandscapeFlowEdge[]>([]);

  const hide_down_dev = ref(false);
  const hide_docker_dev = ref(false);

  const nodes_index_map = computed(() => {
    let map = new Map();
    for (const [index, node] of topo_nodes.value.entries()) {
      map.set(node.id, index);
    }
    return map;
  });

  function update_topo(
    new_value: LandscapeFlowNode[],
    old_value: LandscapeFlowNode[]
  ) {
    let new_value_f = new_value;

    let { addedNodes, removedNodes } = compare_devs(new_value_f, old_value);
    // console.log(addedNodes);
    // console.log(removedNodes);
    if (addedNodes.length != 0) {
      for (const node of addedNodes) {
        topo_nodes.value.push(node);

        let edge = node.create_edge();
        if (edge !== undefined) {
          topo_edges.value.push(edge);
        }
      }
    }
    if (removedNodes.length != 0) {
      let remove_index = new Set();
      let remove_edge = new Set();
      for (const dev_info of removedNodes) {
        remove_index.add(dev_info.id);
        remove_edge.add(dev_info.id);
      }
      // console.log(remove_index);
      topo_nodes.value = topo_nodes.value.filter(
        (node) => !remove_index.has(node.id)
      );
      topo_edges.value = topo_edges.value.filter(
        (node) =>
          !(remove_edge.has(node.source) || remove_edge.has(node.target))
      );
    }

    let position = new PosotionCalculator();
    if (addedNodes.length != 0 || removedNodes.length != 0) {
      for (const node of topo_nodes.value) {
        position.get_position(node);
      }
    }
  }
  //   watch(devs, async (new_value, old_value) => {
  //     update_topo(new_value, old_value)
  //   });

  async function UPDATE_INFO() {
    let new_devs = await ifaces();
    let dev_id_iface_name_map = new Map<number, string>();
    for (const net_dev of new_devs) {
      dev_id_iface_name_map.set(net_dev.index, net_dev.name);
    }
    let new_docker_nets = await get_all_docker_networks();
    let docker_map = new Map<string, LandscapeDockerNetwork>();
    for (const docker_dev of new_docker_nets) {
      docker_map.set(docker_dev.iface_name, docker_dev);
    }

    let new_nodes = [];
    for (const net_dev of new_devs) {
      if (net_dev.controller_id != null && net_dev.controller_name == null) {
        net_dev.controller_name = dev_id_iface_name_map.get(
          net_dev.controller_id
        );
      }
      if (hide_down_dev.value) {
        if (net_dev.dev_status.t === DevStateType.Down) {
          continue;
        }
      }

      if (net_dev.controller_name != null) {
        if (hide_docker_dev.value) {
          let docker_dev = docker_map.get(net_dev.controller_name);
          if (docker_dev !== undefined) {
            continue;
          }
        }
      }

      let docker_dev = docker_map.get(net_dev.name);
      if (docker_dev === undefined) {
        new_nodes.push(
          new LandscapeFlowNode({
            id: `${net_dev.name}`,
            label: net_dev.name,
            position: { x: 0, y: 0 },
            data: { t: FlowNodeType.Dev, dev: net_dev },
          })
        );
      } else {
        new_nodes.push(
          new LandscapeFlowNode({
            id: `${net_dev.name}`,
            label: net_dev.name,
            position: { x: 0, y: 0 },
            data: {
              t: FlowNodeType.Docker,
              dev: net_dev,
              docker_info: docker_dev,
            },
          })
        );
      }
    }

    // console.log(new_nodes);
    update_topo(new_nodes, nodes.value);
    nodes.value = new_nodes;
    devs.value = new_devs;
  }

  function UPDATE_HIDE(value: boolean) {
    hide_down_dev.value = value;
  }

  function UPDATE_DOCKER_HIDE(value: boolean) {
    hide_docker_dev.value = value;
  }

  function FIND_BRIDGE_BY_IFNAME(name: string): boolean {
    let data = FIND_DEV_BY_IFNAME(name);
    if (data !== undefined && data.dev_kind === "Bridge") {
      return true;
    }
    return false;
  }

  function FIND_DEV_BY_IFNAME(name: string): NetDev | undefined {
    for (const dev of devs.value) {
      if (dev.name == name) {
        return dev;
      }
    }
    return undefined;
  }

  return {
    topo_nodes,
    topo_edges,
    hide_down_dev,
    hide_docker_dev,
    nodes_index_map,
    UPDATE_INFO,
    UPDATE_HIDE,
    UPDATE_DOCKER_HIDE,
    FIND_BRIDGE_BY_IFNAME,
    FIND_DEV_BY_IFNAME,
  };
});

function compare_devs(
  new_value: LandscapeFlowNode[],
  old_value: LandscapeFlowNode[]
): {
  addedNodes: LandscapeFlowNode[];
  removedNodes: LandscapeFlowNode[];
} {
  let new_nodes = [...new_value];
  let old_nodes = [...old_value];

  const newIds = new Set(new_nodes.map((node) => node.id));
  const oldIds = new Set(old_nodes.map((node) => node.id));

  const addedNodes = new_nodes.filter((node) => !oldIds.has(node.id));
  const removedNodes = old_nodes.filter((node) => !newIds.has(node.id));

  return { addedNodes, removedNodes };
}
