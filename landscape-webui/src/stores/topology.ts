import { computed, nextTick, ref, watch } from "vue";
import { defineStore } from "pinia";
import { useVueFlow, type Edge, type Node } from "@vue-flow/core";
import {
  FlowNodeType,
  LandscapeFlowEdge,
  LandscapeFlowNode,
  PosotionCalculator,
} from "@/lib/topology";
import { DevStateType, NetDev } from "@/lib/dev";
import { new_ifaces } from "@/api/iface";
import { get_all_docker_networks } from "@/api/docker/network";
import { LandscapeDockerNetwork } from "@/lib/docker/network";
import { UnfoldLessFilled } from "@vicons/material";
import type { IfaceInfo, RawIfaceInfo } from "landscape-types/api/schemas";

type DevInfo = IfaceInfo | RawIfaceInfo;

type NodePositionCache = {
  [nodeId: string]: { x: number; y: number };
};

export const useTopologyStore = defineStore("topology", () => {
  const nodes = ref<LandscapeFlowNode[]>([]);
  const devs = ref<DevInfo[]>([]);

  const topo_nodes = ref<LandscapeFlowNode[]>([]);
  const topo_edges = ref<LandscapeFlowEdge[]>([]);

  const hide_down_dev = ref(true);
  const hide_docker_dev = ref(false);

  // 位置缓存
  const position_cache = ref<NodePositionCache>({});

  // 从localStorage加载位置缓存
  function load_position_cache() {
    try {
      const cached = localStorage.getItem("topology-position-cache");
      if (cached) {
        position_cache.value = JSON.parse(cached);
      } else {
        position_cache.value = {};
      }
    } catch (error) {
      console.error("Failed to load position cache:", error);
      position_cache.value = {};
    }
  }

  // 保存位置缓存到localStorage
  function save_position_cache() {
    try {
      localStorage.setItem(
        "topology-position-cache",
        JSON.stringify(position_cache.value),
      );
    } catch (error) {
      console.error("Failed to save position cache:", error);
    }
  }

  // 清除位置缓存
  function clear_position_cache() {
    position_cache.value = {};
    localStorage.removeItem("topology-position-cache");
  }

  // 保存单个节点位置
  function save_node_position(
    nodeId: string,
    position: { x: number; y: number },
    isUserDragged: boolean = false,
  ) {
    position_cache.value[nodeId] = position;
    save_position_cache();
  }

  // 获取节点缓存位置
  function get_cached_position(
    nodeId: string,
  ): { x: number; y: number } | null {
    return position_cache.value[nodeId] || null;
  }

  const nodes_index_map = computed(() => {
    let map = new Map();
    for (const [index, node] of topo_nodes.value.entries()) {
      map.set(node.id, index);
    }
    return map;
  });

  async function update_topo(
    new_value: LandscapeFlowNode[],
    old_value: LandscapeFlowNode[],
  ) {
    topo_nodes.value = [];
    topo_edges.value = [];
    await nextTick();
    // console.log(addedNodes);
    // console.log(removedNodes);
    if (new_value.length != 0) {
      for (const node of new_value) {
        topo_nodes.value.push(node);

        let edge = node.create_edge();
        if (edge !== undefined) {
          topo_edges.value.push(edge);
        }
      }
    }
    let position = new PosotionCalculator(
      (nodeId: string) => get_cached_position(nodeId),
      (nodeId: string, position: { x: number; y: number }) =>
        save_node_position(nodeId, position, false),
    );
    if (new_value.length != 0) {
      for (const node of topo_nodes.value) {
        position.get_position(node);
      }
    }
  }

  // function update_topo(
  //   new_value: LandscapeFlowNode[],
  //   old_value: LandscapeFlowNode[]
  // ) {
  //   let new_value_f = new_value;

  //   let { addedNodes, removedNodes } = compare_devs(new_value_f, old_value);
  //   // console.log(addedNodes);
  //   // console.log(removedNodes);
  //   if (addedNodes.length != 0) {
  //     for (const node of addedNodes) {
  //       topo_nodes.value.push(node);

  //       let edge = node.create_edge();
  //       if (edge !== undefined) {
  //         topo_edges.value.push(edge);
  //       }
  //     }
  //   }
  //   if (removedNodes.length != 0) {
  //     let remove_index = new Set();
  //     let remove_edge = new Set();
  //     for (const dev_info of removedNodes) {
  //       remove_index.add(dev_info.id);
  //       remove_edge.add(dev_info.id);
  //     }
  //     // console.log(remove_index);
  //     topo_nodes.value = topo_nodes.value.filter(
  //       (node) => !remove_index.has(node.id)
  //     );
  //     topo_edges.value = topo_edges.value.filter(
  //       (node) =>
  //         !(remove_edge.has(node.source) || remove_edge.has(node.target))
  //     );
  //   }

  //   let position = new PosotionCalculator();
  //   if (addedNodes.length != 0 || removedNodes.length != 0) {
  //     for (const node of topo_nodes.value) {
  //       position.get_position(node);
  //     }
  //   }
  // }
  //   watch(devs, async (new_value, old_value) => {
  //     update_topo(new_value, old_value)
  //   });

  async function UPDATE_INFO() {
    // 加载位置缓存
    load_position_cache();

    let { managed, unmanaged } = await new_ifaces();
    let new_docker_nets = await get_all_docker_networks();

    if (hide_down_dev.value) {
      managed = managed.filter((e) => {
        if (e.status) {
          return e.status.dev_status.t === "up";
        }
        return false;
      });
    }
    let dev_id_iface_name_map = new Map<number, string>();
    for (const net_dev of unmanaged) {
      dev_id_iface_name_map.set(
        net_dev.status.index,
        net_dev.status.iface_name,
      );
    }
    for (const net_dev of managed) {
      if (net_dev.status) {
        dev_id_iface_name_map.set(
          net_dev.status.index,
          net_dev.status.iface_name,
        );
      }
    }
    // console.log(new_docker_nets);
    // console.log(managed);
    // console.log(unmanaged);

    // docker 的所有网卡
    let docker_map = new Map<string, LandscapeDockerNetwork>();
    for (const docker_dev of new_docker_nets) {
      docker_map.set(docker_dev.iface_name, docker_dev);
    }

    // 先过滤出所有 docker 网卡
    let docker_dev = [];
    //
    let dev_data_managed_with_docker_child = [];
    let dev_data_unmanaged_with_docker_child = [];
    let docker_ifindexs = new Map<number, string>();

    for (const net_dev of managed) {
      const docker_data = docker_map.get(net_dev.config.name);
      if (docker_data) {
        docker_dev.push(
          new LandscapeFlowNode({
            id: `${net_dev.config.name}`,
            label: net_dev.config.name,
            position: { x: 0, y: 0 },
            data: {
              t: FlowNodeType.ManagedDocker,
              dev: net_dev,
              docker_data,
            },
          }),
        );
        if (net_dev.status) {
          docker_ifindexs.set(net_dev.status.index, net_dev.status.iface_name);
        }
      } else {
        dev_data_managed_with_docker_child.push(net_dev);
      }
    }

    for (const net_dev of unmanaged) {
      const docker_data = docker_map.get(net_dev.status.iface_name);
      if (docker_data) {
        docker_dev.push(
          new LandscapeFlowNode({
            id: `${net_dev.status.iface_name}`,
            label: net_dev.status.iface_name,
            position: { x: 0, y: 0 },
            data: {
              t: FlowNodeType.UnManagedDocker,
              dev: net_dev,
              docker_data,
            },
          }),
        );
        docker_ifindexs.set(net_dev.status.index, net_dev.status.iface_name);
      } else {
        dev_data_unmanaged_with_docker_child.push(net_dev);
      }
    }

    let docker_leafs = [];
    const iface_nodes = [];
    for (const dev of dev_data_managed_with_docker_child) {
      // TODO: 当 config 有 controller 但是 id 却是 空的 节点上需要有提示
      if (
        dev.status &&
        dev.status.controller_id &&
        docker_ifindexs.has(dev.status.controller_id)
      ) {
        /// docker 连接的叶子节点, 正常要为空
        continue;
      }
      iface_nodes.push(
        new LandscapeFlowNode({
          id: `${dev.config.name}`,
          label: dev.config.name,
          parent: dev.config.controller_name,
          position: { x: 0, y: 0 },
          data: { t: FlowNodeType.Managed, dev },
        }),
      );
    }

    // console.log(docker_ifindexs);
    for (const dev of dev_data_unmanaged_with_docker_child) {
      if (dev.status.controller_id) {
        let docker_parent = docker_ifindexs.get(dev.status.controller_id);
        if (docker_parent) {
          /// docker 连接的叶子节点
          docker_leafs.push(
            new LandscapeFlowNode({
              id: `${dev.status.iface_name}`,
              label: dev.status.iface_name,
              parent: docker_parent,
              position: { x: 0, y: 0 },
              data: { t: FlowNodeType.DockerLeaf, dev },
            }),
          );
          continue;
        }
      }

      if (hide_down_dev.value) {
        continue;
      }

      let parent = null;
      if (dev.status.controller_id) {
        parent = dev_id_iface_name_map.get(dev.status.controller_id);
      }
      iface_nodes.push(
        new LandscapeFlowNode({
          id: `${dev.status.iface_name}`,
          label: dev.status.iface_name,
          parent,
          position: { x: 0, y: 0 },
          data: { t: FlowNodeType.UnManaged, dev },
        }),
      );
    }

    if (hide_docker_dev.value) {
      docker_leafs = [];
    }

    const new_nodes = [...iface_nodes, ...docker_dev, ...docker_leafs];
    // console.log(new_nodes);
    // console.log(docker_leafs);
    await update_topo(new_nodes, nodes.value);
    nodes.value = new_nodes;
    // devs.value = new_devs;
  }

  function UPDATE_HIDE(value: boolean) {
    hide_down_dev.value = value;
  }

  function UPDATE_DOCKER_HIDE(value: boolean) {
    hide_docker_dev.value = value;
  }

  function FIND_BRIDGE_BY_IFNAME(name: string): boolean {
    let data = FIND_DEV_BY_IFNAME(name);
    if (data !== undefined && data.dev_kind === "bridge") {
      return true;
    }
    return false;
  }

  function FIND_DEV_BY_IFNAME(name: string): NetDev | undefined {
    // for (const dev of devs.value) {
    //   if (dev.name == name) {
    //     return dev;
    //   }
    // }
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
    // 位置缓存相关方法
    save_node_position,
    clear_position_cache,
  };
});

function compare_devs(
  new_value: LandscapeFlowNode[],
  old_value: LandscapeFlowNode[],
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
